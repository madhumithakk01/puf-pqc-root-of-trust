/*
 * Wi-Fi bring-up: join the 2.4 GHz WPA2 network, print the address, and send
 * the UDP beacon "PQW1 <device> <ip> 7000 <version> <svn>" every two seconds
 * so a laptop can find the board without knowing its address.
 */

#include <stdio.h>
#include <string.h>

#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#define BEACON_PORT 7001

int main(void)
{
    stdio_init_all();
    sleep_ms(2000);
    if (cyw43_arch_init()) {
        printf("cyw43 init failed\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();
    printf("joining %s ...\n", WIFI_SSID);
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("RESULT FAIL: could not join\n");
        return 1;
    }
    printf("joined, ip %s\n", ip4addr_ntoa(netif_ip4_addr(netif_default)));
    printf("RESULT PASS\n");

    cyw43_arch_lwip_begin();
    struct udp_pcb *pcb = udp_new();
    cyw43_arch_lwip_end();

    for (unsigned n = 0;; n++) {
        char msg[96];
        int len = snprintf(msg, sizeof msg, "PQW1 wifichk %s 7000 0.0.0 %u",
                           ip4addr_ntoa(netif_ip4_addr(netif_default)), n);
        cyw43_arch_lwip_begin();
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
        if (p) {
            memcpy(p->payload, msg, (size_t)len);
            udp_sendto(pcb, p, IP_ADDR_BROADCAST, BEACON_PORT);
            pbuf_free(p);
        }
        cyw43_arch_lwip_end();
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, n & 1);
        sleep_ms(2000);
    }
}
