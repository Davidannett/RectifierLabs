#include <Adafruit_NeoPixel.h>
#ifdef __AVR__
  #include <avr/power.h>
#endif

#define PIN 6

// Parameter 1 = number of pixels in strip
// Parameter 2 = Arduino pin number (most are valid)
// Parameter 3 = pixel type flags, add together as needed:
//   NEO_KHZ800  800 KHz bitstream (most NeoPixel products w/WS2812 LEDs)
//   NEO_KHZ400  400 KHz (classic 'v1' (not v2) FLORA pixels, WS2811 drivers)
//   NEO_GRB     Pixels are wired for GRB bitstream (most NeoPixel products)
//   NEO_RGB     Pixels are wired for RGB bitstream (v1 FLORA pixels, not v2)
Adafruit_NeoPixel strip = Adafruit_NeoPixel(8, PIN, NEO_GRB + NEO_KHZ800);

void setup() {
srip.begin();
  strip.show(); // Initialize all pixels to 'off'
}

void loop() {
//Written by: Jason Yandell

int TOTAL_LEDS = 8;
float MaximumBrightness = 255;
float SpeedFactor = 0.008; // I don't actually know what would look good
float StepDelay = 5; // ms for a step delay on the lights

// Make the lights breathe
for (int i = 0; i < 65535; i++) {
// Intensity will go from 10 - MaximumBrightness in a "breathing" manner
float intensity = MaximumBrightness /2.0 * (1.0 + sin(SpeedFactor * i));
strip.setBrightness(intensity);
// Now set every LED to that color
for (int ledNumber=0; ledNumber<TOTAL_LEDS; ledNumber++) {
strip.setPixelColor(ledNumber, 0, 0, 255);
}

strip.show();
//Wait a bit before continuing to breathe
delay(StepDelay);

}
}


