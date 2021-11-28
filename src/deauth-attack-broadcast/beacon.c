#include <stdio.h>
#include <stdint.h>

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




struct fake_beacon create_beacon_frame();



