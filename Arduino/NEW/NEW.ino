#include <LiquidCrystal.h>
LiquidCrystal lcd(12, 11, 5, 4, 3, 2);
const int UVPanelPin = 10;
const int startbuttonPin = 7;
int startbuttonState = 0;

void setup() 
{
  lcd.begin(16, 2);
  Serial.begin(9600);
  pinMode(startbuttonPin, INPUT_PULLUP);
  pinMode(UVPanelPin, OUTPUT);
  digitalWrite(UVPanelPin, LOW);
}

void loop() 
{
startbuttonState = digitalRead(startbuttonPin);
      if (startbuttonState == LOW) 
        {
      expose();
        } 
      else 
        {
          seriallow();
          waiting();
        } 
}

void expose()
{
  lcd.noAutoscroll();
  digitalWrite(UVPanelPin, HIGH);
  lcd.clear();
  Serial.write("EXPOSING!");
  Serial.println("");
  lcd.setCursor(0, 0);
  lcd.print("EXPOSING!");
  delay(5000);
  digitalWrite(UVPanelPin, LOW);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("    EXPOSED   ");
  delay(500);
}
void seriallow()
{
  
}
void waiting()
{
  Serial.write("Waiting to Start");
  Serial.println("");
  lcd.autoscroll();
  lcd.setCursor(0, 0);
  lcd.print("Waiting to Start");
}
