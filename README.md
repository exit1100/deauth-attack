<b>※ 주의사항</b> <br>
아래 공격 코드는 연구 목적으로 작성된 것이며, 허가 받지 않은 공간에서는 테스트를 절대 금지합니다. <br>
악의 적인 목적으로 이용할 시 발생할 수 있는 법적 책임은 자신한테 있습니다. 이는 해당 글을 열람할 때 동의하였다는 것을 의미합니다.  
  
# deauth-attack-broadcast
AP 목록파일에 저장된 AP에 연결된 모든 station의 연결을 해제한다. <br>
출발지는 AP의 MAC 주소, 목적지는 broadcast(FF:FF:FF:FF:FF:FF)로 만들어진 가짜 인증 해제 패킷을 날려 특정 AP에 연결된 모든 기기들의 연결을 해제 시킬 수 있다. <br><br>
사용방법 : [프로그램 경로] [인터페이스 이름] [AP 목록파일 경로] <br>
ex) ./deauth-attack-broadcast wlan0 AP_List.txt <br><br>
<img width="472" alt="11" src="https://user-images.githubusercontent.com/85146195/143769949-63fd0bef-8d03-406b-b8b6-f9976ea08745.png">


# deauth-attack-whitelist
한 개의 AP에 대해 허용할 기기의 MAC 주소를 제외한 주변의 모든 기기들만 연결을 해제한다. <br>
내가 지정한 기기의 MAC 주소를 파일로 저장(whitelist)하여 저장된 기기만 연결을 유지하고 나머지 주변 모든 기기들은 AP와의 연결을 해제 시킬 수 있다. <br><br>
사용방법 : [프로그램 경로] [인터페이스 이름] [AP MAC 주소] [AP와 연결을 끊을 station MAC 주소] [허용할 station MAC 주소] <br>
ex) ./deauth-attack-whitelist wlan0 AA:BB:CC:DD:EE:FF station_mac.txt white_list.txt <br><br>
<img width="635" alt="22" src="https://user-images.githubusercontent.com/85146195/143770499-7e6e61d0-74dc-423e-91dc-7b2ccae77444.png">
<br><br>
허용 시킬 station MAC 주소는 white_list.txt파일 저장하고, 연결을 해제하는 station MAC 주소는 프로그램이 실행된 상태에서 probe request 패킷을 동적으로 수집하여 주변 기기의 MAC 주소를 수집한다.<br>
각 txt파일 속의 MAC 주소는 아래 그림과 같이 입력하면 되고, 마지막 MAC 주소 뒤에 줄바꿈을 꼭 추가해주어야 한다.<br><br>
<img width="241" alt="33" src="https://user-images.githubusercontent.com/85146195/143770759-98c576e8-2636-47ba-865f-4e26d1f13e8b.png"><br>
주변의 AP 기기의 MAC주소 스캔 : https://github.com/exit1100/beacon_frame_capture -> beacon_frame_wifilist


# deauth-attack-all
주변에 검색되는 모든 AP에 연결할 수 없다. <br>
비콘프레임의 MAC 주소를 수집하여 출발지 MAC으로 설정하고, broadcast(FF:FF:FF:FF:FF:FF)로 인증 해제 패킷을 날린다.<br><br>
사용방법 : [프로그램 경로] [인터페이스 이름]<br>
ex) ./deauth-attack-all wlan0 <br><br>
<img width="476" alt="aa" src="https://user-images.githubusercontent.com/85146195/149347761-4636fe2f-fd6b-46fb-b71a-6966571b5dc8.png">
