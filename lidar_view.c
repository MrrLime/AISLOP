/*
 * lidar_view.c - Radarbild fuer die LiDAR-Daten des ESP32
 *
 * Empfaengt die AES-verschluesselten UDP-Pakete des ESP32 (Port 5001),
 * entschluesselt sie und zeigt die Messpunkte als Radarbild an.
 *
 * Paketformat (siehe encryptPoints() im ESP32-Code), je 16-Byte-Block:
 *   4 Punkte a 4 Byte: Winkel (uint16 LE, Grad * 64), Distanz (uint16 LE, mm * 4)
 *
 * Hinweise zur aktuellen ESP32-Firmware:
 *   - Die Daten werden dort ZWEIMAL mit AES verschluesselt (encryptPoints() und
 *     sendSensorData()). Daher wird hier standardmaessig zweimal entschluesselt.
 *     Mit -s wird nur einmal entschluesselt.
 *   - Der ESP32 liest den LiDAR nur aus, solange ein TCP-Client an Port 5000
 *     verbunden ist, z.B.:   nc 192.168.4.100 5000
 *
 * Bauen (Raspberry Pi / Linux):
 *   sudo apt install libsdl2-dev libssl-dev
 *   gcc -O2 -Wall -o lidar_view lidar_view.c $(sdl2-config --cflags --libs) -lcrypto -lm
 *
 * Aufruf:
 *   ./lidar_view [-p PORT] [-s]
 *
 * Bedienung:
 *   Mausrad / + / -   Zoom
 *   c                 Punkte loeschen
 *   q / Esc           Beenden
 */

#include <SDL.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define DEFAULT_PORT    5001
#define BLOCK_SIZE      16
#define POINTS_PER_BLOCK 4
#define NUM_BINS        720          /* 0,5 Grad pro Bin */
#define FADE_MS         1000         /* Punkte verblassen nach dieser Zeit */
#define WIN_SIZE        800
#define RANGE_MIN_M     0.5f
#define RANGE_MAX_M     40.0f

static const uint8_t AES_KEY[16] = {
    0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
    0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B
};

static int aes_ecb_decrypt(const uint8_t *in, int len, uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outl = 0, finl = 0, ok = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, AES_KEY, NULL) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);   /* kein PKCS#7-Padding */
        if (EVP_DecryptUpdate(ctx, out, &outl, in, len) == 1 &&
            EVP_DecryptFinal_ex(ctx, out + outl, &finl) == 1) {
            ok = 1;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? outl + finl : -1;
}

/* ---------- Punktspeicher ---------- */

typedef struct {
    float angleDeg;
    float distMm;
    Uint32 time;     /* SDL_GetTicks() beim Empfang, 0 = leer */
} Bin;

static Bin bins[NUM_BINS];
static float lastAngle = -1.0f;

/* Statistik (Zaehler seit letzter Titel-Aktualisierung) */
static unsigned cntPackets, cntPoints, cntScans, cntErrors;
static unsigned long totalErrors;

static void storePoint(float angle, float dist, Uint32 now) {
    int idx = (int)(angle * 2.0f);
    if (idx < 0 || idx >= NUM_BINS) return;
    bins[idx].angleDeg = angle;
    bins[idx].distMm = dist;
    bins[idx].time = now ? now : 1;

    /* Neue Umdrehung am Winkelsprung erkennen (z.B. 359 Grad -> 1 Grad) */
    if (lastAngle > 300.0f && angle < 60.0f) cntScans++;
    lastAngle = angle;
    cntPoints++;
}

static void decodeBlock(const uint8_t *p, Uint32 now) {
    for (int i = 0; i < POINTS_PER_BLOCK; i++) {
        const uint8_t *q = p + i * 4;
        uint16_t angleQ6 = (uint16_t)(q[0] | (q[1] << 8));
        uint16_t distQ2  = (uint16_t)(q[2] | (q[3] << 8));
        float angle = angleQ6 / 64.0f;
        float dist  = distQ2 / 4.0f;
        if (distQ2 == 0 || angle >= 360.0f) continue;   /* ungueltiger Punkt */
        storePoint(angle, dist, now);
    }
}

/* Alle anstehenden UDP-Pakete abholen und verarbeiten */
static void receivePackets(int fd, int decryptRounds) {
    uint8_t buf[512], tmp[512], plain[512];
    Uint32 now = SDL_GetTicks();

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                perror("recv");
            return;
        }
        cntPackets++;

        if (n == 0 || n % BLOCK_SIZE != 0) {
            cntErrors++;
            continue;
        }

        const uint8_t *src = buf;
        int len = (int)n;
        int ok = 1;
        for (int r = 0; r < decryptRounds; r++) {
            uint8_t *dst = (r % 2 == 0) ? tmp : plain;
            if (aes_ecb_decrypt(src, len, dst) != len) { ok = 0; break; }
            src = dst;
        }
        if (!ok) { cntErrors++; continue; }

        for (int off = 0; off < len; off += BLOCK_SIZE)
            decodeBlock(src + off, now);
    }
}

/* ---------- Zeichnen ---------- */

static void drawCircle(SDL_Renderer *r, int cx, int cy, float radius) {
    enum { SEG = 128 };
    SDL_Point pts[SEG + 1];
    for (int i = 0; i <= SEG; i++) {
        double a = 2.0 * M_PI * i / SEG;
        pts[i].x = cx + (int)lround(radius * cos(a));
        pts[i].y = cy + (int)lround(radius * sin(a));
    }
    SDL_RenderDrawLines(r, pts, SEG + 1);
}

static float ringStepM(float rangeM) {
    if (rangeM <= 2.0f)  return 0.5f;
    if (rangeM <= 12.0f) return 1.0f;
    if (rangeM <= 25.0f) return 2.0f;
    return 5.0f;
}

static void render(SDL_Renderer *r, float rangeM) {
    int w, h;
    SDL_GetRendererOutputSize(r, &w, &h);
    int cx = w / 2, cy = h / 2;
    float radiusPx = (float)((w < h ? w : h) / 2 - 10);
    if (radiusPx < 10) radiusPx = 10;
    float pxPerMm = radiusPx / (rangeM * 1000.0f);

    /* Hintergrund */
    SDL_SetRenderDrawColor(r, 5, 15, 8, 255);
    SDL_RenderClear(r);

    /* Entfernungsringe */
    float step = ringStepM(rangeM);
    SDL_SetRenderDrawColor(r, 0, 90, 40, 255);
    for (float m = step; m <= rangeM + 1e-3f; m += step)
        drawCircle(r, cx, cy, m * 1000.0f * pxPerMm);

    /* Fadenkreuz + 30-Grad-Linien */
    SDL_SetRenderDrawColor(r, 0, 60, 28, 255);
    for (int deg = 0; deg < 360; deg += 30) {
        double a = deg * M_PI / 180.0;
        SDL_RenderDrawLine(r, cx, cy,
                           cx + (int)lround(radiusPx * sin(a)),
                           cy - (int)lround(radiusPx * cos(a)));
    }

    /* Sweep-Linie am zuletzt empfangenen Winkel */
    if (lastAngle >= 0.0f) {
        double a = lastAngle * M_PI / 180.0;
        SDL_SetRenderDrawColor(r, 60, 200, 100, 255);
        SDL_RenderDrawLine(r, cx, cy,
                           cx + (int)lround(radiusPx * sin(a)),
                           cy - (int)lround(radiusPx * cos(a)));
    }

    /* Messpunkte: 0 Grad oben, im Uhrzeigersinn */
    Uint32 now = SDL_GetTicks();
    for (int i = 0; i < NUM_BINS; i++) {
        if (bins[i].time == 0) continue;
        Uint32 age = now - bins[i].time;
        if (age >= FADE_MS) continue;

        float bright = 1.0f - (float)age / FADE_MS;
        double a = bins[i].angleDeg * M_PI / 180.0;
        float d = bins[i].distMm * pxPerMm;
        if (d > radiusPx) continue;

        int x = cx + (int)lround(d * sin(a));
        int y = cy - (int)lround(d * cos(a));
        SDL_SetRenderDrawColor(r, (Uint8)(80 * bright),
                               (Uint8)(60 + 195 * bright),
                               (Uint8)(30 + 70 * bright), 255);
        SDL_Rect rc = { x - 1, y - 1, 3, 3 };
        SDL_RenderFillRect(r, &rc);
    }

    /* Sensor in der Mitte */
    SDL_SetRenderDrawColor(r, 255, 80, 80, 255);
    SDL_Rect sensor = { cx - 3, cy - 3, 7, 7 };
    SDL_RenderFillRect(r, &sensor);

    SDL_RenderPresent(r);
}

/* ---------- Hauptprogramm ---------- */

static void usage(const char *prog) {
    fprintf(stderr,
            "Aufruf: %s [-p PORT] [-s]\n"
            "  -p PORT  UDP-Port (Standard %d)\n"
            "  -s       nur einmal entschluesseln (Standard: zweimal, passend zur aktuellen ESP32-Firmware)\n",
            prog, DEFAULT_PORT);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    int decryptRounds = 2;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (port <= 0 || port > 65535) { usage(argv[0]); return 1; }
        } else if (strcmp(argv[i], "-s") == 0) {
            decryptRounds = 1;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    /* UDP-Socket */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    int rcvbuf = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* SDL */
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "SDL_Init: %s\n", SDL_GetError());
        close(fd);
        return 1;
    }
    SDL_Window *win = SDL_CreateWindow("LiDAR Radar",
                                       SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                       WIN_SIZE, WIN_SIZE,
                                       SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    if (!win) {
        fprintf(stderr, "SDL_CreateWindow: %s\n", SDL_GetError());
        SDL_Quit();
        close(fd);
        return 1;
    }
    SDL_Renderer *ren = SDL_CreateRenderer(win, -1,
                                           SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!ren) ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_SOFTWARE);
    if (!ren) {
        fprintf(stderr, "SDL_CreateRenderer: %s\n", SDL_GetError());
        SDL_DestroyWindow(win);
        SDL_Quit();
        close(fd);
        return 1;
    }

    printf("Warte auf LiDAR-Daten auf UDP-Port %d (%dx entschluesseln) ...\n",
           port, decryptRounds);
    printf("Hinweis: Der ESP32 sendet nur, solange ein TCP-Client an Port 5000 verbunden ist.\n");

    float rangeM = 6.0f;
    Uint32 lastStats = SDL_GetTicks();
    int running = 1;

    while (running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            switch (ev.type) {
            case SDL_QUIT:
                running = 0;
                break;
            case SDL_MOUSEWHEEL:
                if (ev.wheel.y > 0) rangeM /= 1.2f;
                else if (ev.wheel.y < 0) rangeM *= 1.2f;
                break;
            case SDL_KEYDOWN:
                switch (ev.key.keysym.sym) {
                case SDLK_ESCAPE:
                case SDLK_q:
                    running = 0;
                    break;
                case SDLK_PLUS:
                case SDLK_KP_PLUS:
                case SDLK_EQUALS:
                    rangeM /= 1.2f;
                    break;
                case SDLK_MINUS:
                case SDLK_KP_MINUS:
                    rangeM *= 1.2f;
                    break;
                case SDLK_c:
                    memset(bins, 0, sizeof(bins));
                    lastAngle = -1.0f;
                    break;
                default:
                    break;
                }
                break;
            default:
                break;
            }
        }
        if (rangeM < RANGE_MIN_M) rangeM = RANGE_MIN_M;
        if (rangeM > RANGE_MAX_M) rangeM = RANGE_MAX_M;

        receivePackets(fd, decryptRounds);
        render(ren, rangeM);

        /* Statistik im Fenstertitel, 2x pro Sekunde */
        Uint32 now = SDL_GetTicks();
        Uint32 dt = now - lastStats;
        if (dt >= 500) {
            float s = dt / 1000.0f;
            totalErrors += cntErrors;
            char title[256];
            snprintf(title, sizeof(title),
                     "LiDAR Radar | Bereich %.1f m (Ringe %.1f m) | %.0f Pakete/s | "
                     "%.0f Punkte/s | %.1f Scans/s | Fehler %lu",
                     rangeM, ringStepM(rangeM), cntPackets / s, cntPoints / s,
                     cntScans / s, totalErrors);
            SDL_SetWindowTitle(win, title);
            cntPackets = cntPoints = cntScans = cntErrors = 0;
            lastStats = now;
        }

        SDL_Delay(5);
    }

    SDL_DestroyRenderer(ren);
    SDL_DestroyWindow(win);
    SDL_Quit();
    close(fd);
    return 0;
}
