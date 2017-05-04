#include <Adafruit_NeoPixel.h>

#define N_PIXELS  8  // Number of pixels you are using
#define LED_PIN    6  // NeoPixel LED strand is connected to GPIO #0 / D0

Adafruit_NeoPixel  strip = Adafruit_NeoPixel(N_PIXELS, LED_PIN, NEO_GRB + NEO_KHZ800);

void setup() {
  strip.begin();

  //  you can change the brightness to lower if its too bright!
  strip.setBrightness(255);                // Set LED brightness 0-255
  colorWipe(strip.Color(255, 255, 255),0); // fill the strip with all white
  strip.show();                            // Update strip
}

void loop() {
}

// Fill the dots one after the other with a color
void colorWipe(uint32_t c, uint8_t wait) {
  for(uint16_t i=0; i<strip.numPixels(); i++) {
      strip.setPixelColor(i, c);
      strip.show();
  }
}

