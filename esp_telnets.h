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

void esp_telnets_listen(void (*callbackParam)(uint8_t *buffer, size_t size), char *ca, char *cert, char *key);
void esp_telnets_send(uint8_t *buffer, size_t size);
 int esp_telnets_vprintf(const char *fmt, va_list va);
