//pin 5 is set to analog read below


void setup()
{
   Serial.begin(9600);
}
void loop()
{
   Serial.println(analogRead(5));//prints out the analog reading input on A5
   delay(200);//delay
}




//refernence valuses for brightness

//strip.setPixelColor(i, (0, 63, 0));  //1/4 bright green
//strip.setPixelColor(i, (255, 0, 0));  //full-bright red 
//strip.setPixelColor(i, (0, 255, 255)); //full-bright cyan
//strip.setPixelColor(i, (127, 127, 0)); //half-bright yellow
//strip.setPixelColor(i, (255, 192, 255)); //orange
//strip.setPixelColor(i, (63, 63, 63)); //1/4-bright white

//more specific control of brightness
//void loop()
//{
//   strip.setBrightness(255);
//   strip.setPixelColor(n, 255,0,100);
//   strip.show();
//   delay(1000);
//   strip.setBrightness(50);
//   strip.show();
//   delay(1000);
//}
