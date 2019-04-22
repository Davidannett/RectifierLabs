#include <LiquidCrystal.h>
LiquidCrystal lcd(12, 11, 5, 4, 3, 2);


void setup() 
{
  lcd.begin(16, 2);
}

void loop() 
{
  waiting();
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
