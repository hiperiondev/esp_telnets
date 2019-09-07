/*
 * This file is part of the esp-iot-secure-core distribution (https://github.com/hiperiondev/esp-iot-secure-core).
 * Copyright (c) 2019 Emiliano Augusto Gonzalez (comercial@hiperion.com.ar)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Based on: https://github.com/nkolban/esp32-snippets/tree/master/networking/telnet (Neil Kolban <kolban1@kolban.com>)
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/def.h"
#include "lwip/sockets.h"
#include "openssl/ssl.h"
#include "libtelnet/libtelnet.h"
static const char *TAG = "esp_telnets";

#define OPENSSL_SERVER_LOCAL_TCP_PORT 992  // IANA tcp telnets (telnet protocol over TLS/SSL)
#define OPENSSL_SERVER_RECV_BUF_LEN   2048

static telnet_t *tnHandle;
static void (*receivedDataCallback)(uint8_t *buffer, size_t size);
SSL* ssl;

struct telnetUserData {
    int sockfd;
};

/*
 static char *eventToString(telnet_event_type_t type) {
    switch (type) {
    case TELNET_EV_COMPRESS:
        return "TELNET_EV_COMPRESS";
    case TELNET_EV_DATA:
        return "TELNET_EV_DATA";
    case TELNET_EV_DO:
        return "TELNET_EV_DO";
    case TELNET_EV_DONT:
        return "TELNET_EV_DONT";
    case TELNET_EV_ENVIRON:
        return "TELNET_EV_ENVIRON";
    case TELNET_EV_ERROR:
        return "TELNET_EV_ERROR";
    case TELNET_EV_IAC:
        return "TELNET_EV_IAC";
    case TELNET_EV_MSSP:
        return "TELNET_EV_MSSP";
    case TELNET_EV_SEND:
        return "TELNET_EV_SEND";
    case TELNET_EV_SUBNEGOTIATION:
        return "TELNET_EV_SUBNEGOTIATION";
    case TELNET_EV_TTYPE:
        return "TELNET_EV_TTYPE";
    case TELNET_EV_WARNING:
        return "TELNET_EV_WARNING";
    case TELNET_EV_WILL:
        return "TELNET_EV_WILL";
    case TELNET_EV_WONT:
        return "TELNET_EV_WONT";
    case TELNET_EV_ZMP:
        return "TELNET_EV_ZMP";
    }
    return "Unknown type";
}
*/

void esp_telnets_send(uint8_t *buffer, size_t size) {
    if (tnHandle != NULL) {
        telnet_send(tnHandle, (char *) buffer, size);
    }
}

int esp_telnets_vprintf(const char *fmt, va_list va) {
    if (tnHandle == NULL) {
        return 0;
    }
    return telnet_vprintf(tnHandle, fmt, va);
}

static void telnetHandler(telnet_t *thisTelnet, telnet_event_t *event, void *userData) {
    int rc;
    switch (event->type) {
    case TELNET_EV_SEND:
        rc = SSL_write(ssl, event->data.buffer, event->data.size);
        if (rc < 0) {
            ESP_LOGI(TAG, "SSL_write error");
        }
        break;

    case TELNET_EV_DATA:
        if (receivedDataCallback != NULL) {
            receivedDataCallback((uint8_t *) event->data.buffer, (size_t) event->data.size);
        }
        break;

    default:
        break;
    }
}

static void doTelnet(int partnerSocket) {
    static const telnet_telopt_t my_telopts[] = {
            {
                    TELNET_TELOPT_ECHO,
                    TELNET_WILL,
                    TELNET_DONT
            },
            {
                    TELNET_TELOPT_TTYPE,
                    TELNET_WILL,
                    TELNET_DONT
            },
            {
                    TELNET_TELOPT_COMPRESS2,
                    TELNET_WONT,
                    TELNET_DO
            },
            {
                    TELNET_TELOPT_ZMP,
                    TELNET_WONT,
                    TELNET_DO
            },
            {
                    TELNET_TELOPT_MSSP,
                    TELNET_WONT,
                    TELNET_DO
            },
            {
                    TELNET_TELOPT_BINARY,
                    TELNET_WILL,
                    TELNET_DO
            },
            {
                    TELNET_TELOPT_NAWS,
                    TELNET_WILL,
                    TELNET_DONT
            },
            {
                    -1,
                    0,
                    0
            }
    };
    struct telnetUserData *pTelnetUserData = (struct telnetUserData *) malloc(sizeof(struct telnetUserData));
    pTelnetUserData->sockfd = partnerSocket;

    tnHandle = telnet_init(my_telopts, telnetHandler, 0, pTelnetUserData);

    uint8_t buffer[1024];
    while (1) {
        ssize_t len = SSL_read(ssl, buffer, OPENSSL_SERVER_RECV_BUF_LEN - 1);
        if (len == 0) {
            break;
        }
        telnet_recv(tnHandle, (char *) buffer, len);
    }
    telnet_free(tnHandle);
    tnHandle = NULL;
    free(pTelnetUserData);
}

void esp_telnets_listen(void (*callbackParam)(uint8_t *buffer, size_t size), char *ca, char *cert, char *key, uint8_t ssl_verify) {
    int ret;
    SSL_CTX* ctx;
    struct sockaddr_in sock_addr;
    int sockfd, new_sockfd;

    ESP_LOGI(TAG, "create SSL context");
    ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) {
        ESP_LOGI(TAG, "...failed");
        goto failed1;
    }

    ESP_LOGI(TAG, "load ca crt");
    ret = SSL_CTX_load_verify_buffer(ctx, (const unsigned char *) ca, strlen(ca));

    if (!ret) {
        ESP_LOGI(TAG, "...failed");
        goto failed2;
    }

    ESP_LOGI(TAG, "load server crt");
    ret = SSL_CTX_use_certificate_ASN1(ctx, strlen(cert), (const unsigned char *) cert);

    if (!ret) {
        ESP_LOGI(TAG, "...failed");
        goto failed2;
    }

    ESP_LOGI(TAG, "load server private key");
    ret = SSL_CTX_use_PrivateKey_ASN1(0, ctx, (const unsigned char *) key, strlen(key));

    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }

    ESP_LOGI(TAG, "set verify mode verify peer");
    SSL_CTX_set_verify(ctx, ssl_verify, NULL);

    ESP_LOGI(TAG, "create socket");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ESP_LOGI(TAG, "...failed");
        goto failed2;
    }

    ESP_LOGI(TAG, "socket bind ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(OPENSSL_SERVER_LOCAL_TCP_PORT);

    ret = bind(sockfd, (struct sockaddr* )&sock_addr, sizeof(sock_addr));

    if (ret) {
        ESP_LOGI(TAG, "bind failed: %d/%04x", ret, ret);
        goto failed3;
    }

    ESP_LOGI(TAG, "server socket listen");
    ret = listen(sockfd, 32);

    if (ret) {
        ESP_LOGI(TAG, "...failed");
        goto failed3;
    }

    reconnect:
    ESP_LOGI(TAG, "SSL server create");
    ssl = SSL_new(ctx);

    if (!ssl) {
        ESP_LOGI(TAG, "...failed");
        goto failed3;
    }

    socklen_t addr_len;
    receivedDataCallback = callbackParam;

    ESP_LOGI(TAG, "ssl loop");
    while (1) {
        ESP_LOGI(TAG, "socket accept client");
        new_sockfd = accept(sockfd, (struct sockaddr* )&sock_addr, &addr_len);

        if (new_sockfd < 0) {
            ESP_LOGI(TAG, "socket accept client failed");
            goto failed4;
        }

        SSL_set_fd(ssl, new_sockfd);

        ESP_LOGI(TAG, "SSL server accept client ......");
        ret = SSL_accept(ssl);

        if (!ret) {
            ESP_LOGI(TAG, "SSL server accept client failed");
            goto failed5;
        }

        ESP_LOGI(TAG, "new client connection");
        doTelnet(new_sockfd);
    }

    SSL_shutdown(ssl);
    failed5: close(new_sockfd);
    new_sockfd = -1;
    failed4: SSL_free(ssl);
    ssl = NULL;
    goto reconnect;
    failed3: close(sockfd);
    sockfd = -1;
    failed2: SSL_CTX_free(ctx);
    ctx = NULL;
    failed1:
    ESP_LOGI(TAG, "telnet exit");
}
