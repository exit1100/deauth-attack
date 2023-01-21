#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#define NULL 0x00

struct radiotap_header {
    uint8_t     version = 0x00;     /* set to 0 */
    uint8_t     pad = 0x00;
    uint16_t    len = 0x000b;         /* entire length */
    uint32_t    present = 0x00028000;     /* fields present */
    uint8_t     dummy[3] = {0,};
} __attribute__((__packed__));

struct IEEE_802dot11 {
    uint16_t frame_control = 0x00c0;
    uint16_t duration_id = 0x0000;
    uint8_t dhost[6] = {0,};  //목적지 주소
    uint8_t shost[6] = {0,};  //출발지 주소
    uint8_t bssid[6] = {0,};
    uint16_t squence_control = 0x0000;
} __attribute__ ((__packed__));

struct fixed_parameters{
    uint16_t reason_code = 0x0007;
} __attribute__ ((__packed__));

struct beacon_frame{
    struct radiotap_header radiotap;
    struct IEEE_802dot11 becon;
    struct fixed_parameters fixed;
} __attribute__ ((__packed__));


struct multiargs{
    char* dev;
    char* station_mac_list;
    char* white_list;
};

struct beacon_frame create_beacon_frame();
int dump_radiotap(struct radiotap_header *radiotap_header){
    unsigned int len = radiotap_header->len;
    //printf("[Radiotap Length] : %d\n",len);
    return len;
}

unsigned char * dump_beacon_header(struct IEEE_802dot11 *beacon_header)
{
    unsigned int frameControl = htons(beacon_header->frame_control);
    unsigned char *smac = beacon_header->shost;
    //unsigned char *dmac = beacon_header->dhost;
    //unsigned char *bssid = beacon_header->bssid;
    if (frameControl==0x4000){
        /*printf("[FrameControl] : 0x%04x\n", frameControl);
        return smac;
    }
    return NULL;
}

