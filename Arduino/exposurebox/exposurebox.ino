#include <LiquidCrystal.h>

/******************************************************************
 Created with PROGRAMINO IDE for Arduino - 29.04.2017 12:39:39
 Project     : UV PCB Exposure Box
 Libraries   : Liquid Crystal
 Author      : David Annett
 Description : Simple 5 second exposure timer
******************************************************************/
LiquidCrystal lcd(12, 11, 5, 4, 3, 2);
const int UVPanelPin = 10;
const int startbuttonPin = 7;     // the number of the pushbutton pin
int startbuttonState = 0;         // variable for reading the pushbutton status
  

  void setup()
  {
    lcd.begin(16, 2);
  clearscreen();
    //lcd.setCursor(0, 0);
    //lcd.print("                ");
    //lcd.setCursor(0, 1);
    //lcd.print("                ");
    lcd.setCursor(0, 1);
    lcd.print(" opening serial ");  
    Serial.begin(9600);
    pinMode(LED_BUILTIN, OUTPUT);
    pinMode(startbuttonPin, INPUT_PULLUP);
    pinMode(UVPanelPin, OUTPUT);
    digitalWrite(UVPanelPin, LOW);
  }

  void loop()
  {
    startbuttonState = digitalRead(startbuttonPin);
      if (startbuttonState == HIGH) 
        {
      expose();
          //digitalWrite(UVPanelPin, HIGH);
          //int startbuttonState = 0;
          //lcd.setCursor(0, 0);
          //lcd.print("                ");
          //lcd.setCursor(0, 1);
          //lcd.print("                ");
          //lcd.setCursor(0, 0);
          //lcd.print("    EXPOSING    ");
          //Serial.print("in exposure mode");
          //Serial.println("");
          //delay(5000);
          //digitalWrite(UVPanelPin, LOW);
          //lcd.setCursor(0, 0);
          //lcd.print("                ");
          //lcd.setCursor(0, 1);
          //lcd.print("                ");
          //lcd.setCursor(0, 1);
          //lcd.print("    EXPOSED   ");
          //delay(2000);
          //lcd.setCursor(0, 0);
          //lcd.print("                ");
          //lcd.setCursor(0, 1);
          //lcd.print("                ");
        } 
      else 
        {
          Serial.write("pin still LOW");
          Serial.println("");
      waiting();
          //lcd.setCursor(0, 0);
          //lcd.print("Waiting to Start");
          //delay(150);
          //lcd.setCursor(0, 1);
          //lcd.print("     .          ");
          //delay(150);
          //lcd.setCursor(0, 1);
          //lcd.print("     ..         ");
          //delay(150);
          //lcd.setCursor(0, 1);
          //lcd.print("     ...        ");
          //delay(150);
          //lcd.setCursor(0, 1);
          //lcd.print("     ....       ");
          //delay(150);
          //lcd.setCursor(0, 1);
          //lcd.print("     .....      ");
          //delay(150);
          //lcd.setCursor(0, 1);
          //lcd.print("                ");
          //delay(1000);
        } 
    }
void waiting()
{
  lcd.setCursor(0, 0);
  lcd.print("Waiting to Start");
  delay(150);
  lcd.setCursor(0, 1);
  lcd.print("     .          ");
  delay(150);
  lcd.setCursor(0, 1);
  lcd.print("     ..         ");
  delay(150);
  lcd.setCursor(0, 1);
  lcd.print("     ...        ");
  delay(150);
  lcd.setCursor(0, 1);
  lcd.print("     ....       ");
  delay(150);
  lcd.setCursor(0, 1);
  lcd.print("     .....      ");
  delay(150);
  lcd.setCursor(0, 1);
  lcd.print("                ");
  delay(150);
}

void clearscreen()
{
  lcd.setCursor(0, 0);
  lcd.print("                ");
  lcd.setCursor(0, 1);
  lcd.print("                ");
}

void expose()
{
  digitalWrite(UVPanelPin, HIGH);
  int startbuttonState = 0;
  clearscreen();
  //lcd.setCursor(0, 0);
  //lcd.print("                ");
  //lcd.setCursor(0, 1);
  //lcd.print("                ");
  ;lcd.setCursor(0, 0);
  lcd.print("    EXPOSING    ");
  Serial.print("in exposure mode");
  Serial.println("");
  delay(5000);
  digitalWrite(UVPanelPin, LOW);
  clearscreen();
  //lcd.setCursor(0, 0);
  //lcd.print("                ");
  //lcd.setCursor(0, 1);
  //lcd.print("                ");
  lcd.setCursor(0, 1);
  lcd.print("    EXPOSED   ");
  delay(2000);
  clearscreen();
  //lcd.setCursor(0, 0);
  //lcd.print("                ");
  //lcd.setCursor(0, 1);
  //lcd.print("                ");
}

