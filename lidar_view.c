/*
 * lidar_view.c - zeigt die LiDAR-Punkte vom ESP32 in einem SDL2-Fenster an
 *
 * sudo apt install libsdl2-dev libssl-dev
 * gcc -O2 -Wall -o lidar_view lidar_view.c $(sdl2-config --cflags --libs) -lcrypto -lm
 */

#include <SDL2/SDL.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define UDP_PORT     5001
#define WIN_SIZE     800
#define RANGE_MM     6000.0f   /* Distanz bis zum Fensterrand */
#define NUM_BINS     720       /* 0,5 Grad pro Bin */
#define POINT_TTL_MS 1000      /* Punkte nach 1 s ausblenden */

static const uint8_t AES_KEY[16] = {
    0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
    0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B
};

static float    bin_dist[NUM_BINS];
static uint32_t bin_time[NUM_BINS];

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

/* alle anstehenden UDP-Pakete abholen und Punkte speichern */
static void receive_points(int fd) {
    uint8_t buf[256], plain[256];
    uint32_t now = SDL_GetTicks();
    ssize_t n;

    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
        if (n % 16 != 0) continue;
        int plen = aes_ecb_decrypt(buf, (int)n, plain);
        if (plen < 0) continue;

        /* je Punkt 4 Byte: angle_q6, dist_q2 (little-endian) */
        for (int i = 0; i + 3 < plen; i += 4) {
            float angle = (plain[i]     | (plain[i + 1] << 8)) / 64.0f;
            float dist  = (plain[i + 2] | (plain[i + 3] << 8)) / 4.0f;
            if (dist <= 0.0f || angle >= 360.0f) continue;

            int idx = (int)(angle * NUM_BINS / 360.0f);
            bin_dist[idx] = dist;
            bin_time[idx] = now;
        }
    }
}

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "SDL_Init: %s\n", SDL_GetError());
        return 1;
    }
    SDL_Window *win = SDL_CreateWindow("LiDAR", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                       WIN_SIZE, WIN_SIZE, 0);
    SDL_Renderer *ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_PRESENTVSYNC);
    if (!win || !ren) {
        fprintf(stderr, "SDL: %s\n", SDL_GetError());
        return 1;
    }

    const int c = WIN_SIZE / 2;
    const float scale = (WIN_SIZE / 2) / RANGE_MM;   /* Pixel pro mm */
    int running = 1;

    while (running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_QUIT ||
                (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_ESCAPE)) {
                running = 0;
            }
        }

        receive_points(fd);

        SDL_SetRenderDrawColor(ren, 0, 0, 0, 255);
        SDL_RenderClear(ren);

        /* Sensor in der Mitte */
        SDL_SetRenderDrawColor(ren, 255, 0, 0, 255);
        SDL_Rect sensor = { c - 3, c - 3, 7, 7 };
        SDL_RenderFillRect(ren, &sensor);

        /* Punkte: 0 Grad oben, im Uhrzeigersinn */
        SDL_SetRenderDrawColor(ren, 0, 255, 0, 255);
        uint32_t now = SDL_GetTicks();
        for (int i = 0; i < NUM_BINS; i++) {
            if (bin_dist[i] <= 0.0f || now - bin_time[i] > POINT_TTL_MS) continue;
            float t = (i + 0.5f) * 2.0f * (float)M_PI / NUM_BINS;
            int x = c + (int)(bin_dist[i] * scale * sinf(t));
            int y = c - (int)(bin_dist[i] * scale * cosf(t));
            SDL_Rect p = { x - 1, y - 1, 3, 3 };
            SDL_RenderFillRect(ren, &p);
        }

        SDL_RenderPresent(ren);
        SDL_Delay(1);
    }

    SDL_DestroyRenderer(ren);
    SDL_DestroyWindow(win);
    SDL_Quit();
    close(fd);
    return 0;
}
