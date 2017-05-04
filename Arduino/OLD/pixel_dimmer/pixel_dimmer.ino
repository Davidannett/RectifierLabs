// Arduino code for Neopixel LED controller
// using a potentiometer and switch button
// (C) Ismail Uddin, 2015
// www.scienceexposure.com

#include <Adafruit_NeoPixel.h>
#define PIN 3
Adafruit_NeoPixel strip = Adafruit_NeoPixel(8, PIN, NEO_GRB + NEO_KHZ800);

int potPin = 2;
int val = 0;
int colorVal = 0;
int reading = 0;
int x;
int prevVal = 0;
int switchPin = 6;
boolean lastBtn = LOW;
boolean NeopixelColor = false;
boolean lastButton = LOW;


void setup() {
  // put your setup code here, to run once:
  strip.begin();
  strip.show();
  pinMode(switchPin, INPUT);

//setup serial monitor
Serial.begin(9600);  
  Serial.println("--- Start Serial Monitor SEND_RCVE ---");
  Serial.println(); 
}

void loop() {
  // put your main code here, to run repeatedly:
  reading = analogRead(potPin);
    //Serial.println( '\r' );  // Carriage Return
  val = (reading/1024.0) * 13;
  colorVal = (reading/1024.0) * 255;
  Serial.println(reading);
  //Serial.println("      ");
  Serial.println(val);
  //Serial.println("      ");
  Serial.println(colorVal);
  
  if (digitalRead(switchPin) == HIGH && lastButton == LOW)
  {
    delay(250); // Account for contact debounce
    NeopixelColor = !NeopixelColor;
    
  }
  
  if (NeopixelColor == false)
  {
    // Neopixel LED number code
    strip.setBrightness(40);
    if (val != prevVal)
    {
      for ( x = 0; x < val; x++) 
      {
        //strip.setPixelColor(x,255,0,255);
        strip.setPixelColor(x,colorVal,colorVal,colorVal);
      }
      for (x=val; x<13; x++) 
      { 
        strip.setPixelColor(x,0,0,0);
        strip.show();
      }
      prevVal = val;
    }
    else
    {
      strip.show();
    }
    
  }
  else
  {
    // Neopixel Color code
    for (x=0; x < prevVal; x++)
    {
      strip.setPixelColor(x,colorVal,0,255-colorVal);
      strip.show();
    }
  }
}
