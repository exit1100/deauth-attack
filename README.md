<b>※ 주의사항</b> <br>
아래 공격 코드는 연구 목적으로 작성된 것이며, 허가 받지 않은 공간에서는 테스트를 절대 금지합니다. <br>
악의 적인 목적으로 이용할 시 발생할 수 있는 법적 책임은 자신한테 있습니다. 이는 해당 글을 열람할 때 동의하였다는 것을 의미합니다.  
  
# deauth-attack-broadcast
AP 목록파일에 저장된 AP에 연결된 모든 station의 연결을 해제한다. <br>
출발지는 AP의 MAC 주소, 목적지는 broadcast(FF:FF:FF:FF:FF:FF)로 만들어진 가짜 인증 해제 패킷을 날려 특정 AP에 연결된 모든 기기들의 연결을 해제시킬 수 있다. <br><br>
사용방법 : [프로그램 경로] [인터페이스 이름] [AP 목록파일 경로] <br>
ex) ./deauth-attack-broadcast wlan0 AP_List.txt <br><br>

# deauth-attack-whitelist
한개의 AP에 대해 허용할 기기의 MAC 주소를 제외한 주변의 모든 기기들만 연결을 해제한다. <br>
내가 지정한 기기의 MAC 주소를 파일로 저장(whitelist)하여 저장된 기기만 연결을 유지하고 나머지 주변 모든 기기들은 AP와의 연결을 해제시킨다. <br><br>
사용방법 : [프로그램 경로] [인터페이스 이름] [AP MAC 주소] [AP와 연결을 끊을 station MAC 주소] [허용할 station MAC 주소] <br>
ex) ./deauth-attack-whitelist wlan0 AA:BB:CC:DD:EE:FF station_mac.txt white_list.txt <br><br>

