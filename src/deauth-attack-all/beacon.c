#include <stdio.h>
#include <stdint.h>
#define NULL 0x00


struct radiotap_header {
    uint8_t     version;     /* set to 0 */
    uint8_t     pad;
    uint16_t    len;         /* entire length */
    uint32_t    present;     /* fields present */
    uint8_t     dummy[3];
} __attribute__((__packed__));

struct beacon_header{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t dhost[6];  //목적지 주소
    uint8_t shost[6];  //출발지 주소
    uint8_t bssid[6];
    uint16_t squence_control;
} __attribute__ ((__packed__));

struct fixed_parameters{
    uint16_t reason_code;
} __attribute__ ((__packed__));

struct fake_beacon{
    struct radiotap_header radiotap;
    struct beacon_header becon;
    struct fixed_parameters fixed;
} __attribute__ ((__packed__));

struct multiargs{
    char* dev;
    char* AP_mac_list;
};


struct fake_beacon create_beacon_frame();
int dump_radiotap(struct radiotap_header *radiotap_header){
    unsigned int len = radiotap_header->len;
    //printf("[Radiotap Length] : %d\n",len);
    return len;
}

unsigned char * dump_beacon_header(struct beacon_header *beacon_header)
{
    unsigned int frameControl = htons(beacon_header->frame_control);
    unsigned char *smac = beacon_header->shost;
    //unsigned char *dmac = beacon_header->dhost;
    //unsigned char *bssid = beacon_header->bssid;
    if (frameControl==0x8000){
    /*printf("[FrameControl] : 0x%04x\n", frameControl);
    printf("[BEACON] : "\
        "%02x:%02x:%02x:%02x:%02x:%02x -> "\
        "%02x:%02x:%02x:%02x:%02x:%02x\n"\
        "[bssID] : %02x:%02x:%02x:%02x:%02x:%02x\n",
        smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
        dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);*/
        return smac;
    }
    return NULL;
}

