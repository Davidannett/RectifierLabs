#include "Adafruit_NeoPixel.h"
#include "Encoder.h"

// This project includes Adafruit's NeoPixel Library, read about it here: https://learn.adafruit.com/adafruit-neopixel-uberguide
// As well I have included PJRC's (teensy creator) Encoder library, more info here: http://www.pjrc.com/teensy/td_libs_Encoder.html

// IMPORTANT: To reduce NeoPixel burnout risk, add 1000 uF capacitor across
// pixel power leads, add 300 - 500 Ohm resistor on first pixel's data input
// and minimize distance between Arduino and first pixel.  Avoid connecting
// on a live circuit...if you must, connect GND first.
#define PIN 6
#define PIN_ENCODER_SWITCH 3

// According to http://www.pjrc.com/teensy/td_libs_Encoder.html
// for teensy 2.0 we want to use two of the following "5, 6, 7, 8"
// since 6 is already used for the neopixels we will use 5 and 7
Encoder myEnc(5, 7);

//we are useing the 60 pixel rings
#define N_LEDS 8

// Parameter 1 = number of pixels in strip
// Parameter 2 = Arduino pin number (most are valid)
// Parameter 3 = pixel type flags, add together as needed:
//   NEO_KHZ800  800 KHz bitstream (most NeoPixel products w/WS2812 LEDs)
//   NEO_KHZ400  400 KHz (classic 'v1' (not v2) FLORA pixels, WS2811 drivers)
//   NEO_GRB     Pixels are wired for GRB bitstream (most NeoPixel products)
//   NEO_RGB     Pixels are wired for RGB bitstream (v1 FLORA pixels, not v2)
Adafruit_NeoPixel strip = Adafruit_NeoPixel(N_LEDS, PIN, NEO_GRB + NEO_KHZ800);

// Stuff for the encoder
long oldPosition  = -999;
static uint8_t enc_prev_pos   = 0;
static uint8_t enc_flags      = 0;
static char    sw_was_pressed = 0;

// Settings for the larson scanner code

int speed_delay_MAX   = 99;
int speed_delay_MIN   = 0;
// 4*log(x) where x = range[2, 101, 1]
// smaller makes the scanner go faster
float speed_array[] = {4.05465, 9.16291, 12.5276, 15.0408, 17.0475, 18.718, 20.149, 21.4007, 22.5129, 23.5138, 24.4235, 25.2573, 26.0269, 26.7415, 27.4084, 28.0336, 28.622, 29.1777, 29.7041, 30.2042, 30.6805, 31.1352, 31.57, 31.9867, 32.3868, 32.7714, 33.1419, 33.499, 33.8439, 34.1773, 34.4999, 34.8124, 35.1155, 35.4096, 35.6953, 35.9731, 36.2434, 36.5066, 36.763, 37.013, 37.2569, 37.495, 37.7276, 37.9549, 38.1771, 38.3945, 38.6073, 38.8156, 39.0197, 39.2197, 39.4158, 39.6081, 39.7968, 39.982, 40.1638, 40.3424, 40.5178, 40.6903, 40.8598, 41.0264, 41.1904, 41.3517, 41.5104, 41.6667, 41.8205, 41.972, 42.1213, 42.2683, 42.4133, 42.5561, 42.697, 42.8359, 42.9729, 43.108, 43.2413, 43.3729, 43.5028, 43.631, 43.7576, 43.8826, 44.006, 44.128, 44.2485, 44.3675, 44.4852, 44.6014, 44.7164, 44.83, 44.9424, 45.0535, 45.1634, 45.2721, 45.3796, 45.486, 45.5913, 45.6954, 45.7985, 45.9006, 46.0016, 46.1016};
int speed_delay_index   = 19; //start at speed value at array index 19
int speed_delay   = (int) (speed_array[speed_delay_index] );

int brightness_index_MAX   = 99;
int brightness_index_MIN   = 0;
// 255*log10(x) where x=range [1, 10, 0.09]
// Note, there are 101 items in this array, we are just ignoring the last one. I was having trouble generating exacly 100 items
float brightness_array[] ={0., 9.54376, 18.3299, 26.4699, 34.0524, 41.1488, 47.8178, 54.1078, 60.0598, 65.708, 71.0822, 76.2075, 81.1062, 85.7972, 90.2977, 94.6223, 98.7844, 102.796, 106.667, 110.407, 114.025, 117.529, 120.925, 124.22, 127.42, 130.53, 133.555, 136.5, 139.368, 142.164, 144.891, 147.553, 150.152, 152.692, 155.174, 157.602, 159.978, 162.304, 164.583, 166.815, 169.003, 171.149, 173.254, 175.32, 177.348, 179.339, 181.296, 183.218, 185.107, 186.965, 188.792, 190.59, 192.359, 194.1, 195.814, 197.502, 199.164, 200.802, 202.417, 204.007, 205.576, 207.122, 208.648, 210.152, 211.636, 213.101, 214.547, 215.974, 217.382, 218.773, 220.147, 221.504, 222.845, 224.169, 225.478, 226.772, 228.051, 229.315, 230.564, 231.8, 233.023, 234.231, 235.427, 236.61, 237.781, 238.939, 240.085, 241.22, 242.343, 243.455, 244.556, 245.645, 246.725, 247.794, 248.852, 249.901, 250.94, 251.969, 252.988, 253.999, 255.};
int brightness_index   = 8; //start at brightness value at array index 8
unsigned int brightness   = (unsigned int) (brightness_array[brightness_index] );

int buttonState;             // the current reading from the input pin
int lastButtonState = LOW;   // the previous reading from the input pin

// the following variables are long's because the time, measured in miliseconds,
// will quickly become a bigger number than can be stored in an int.
long lastDebounceTime = 0;  // the last time the output pin was toggled
long debounceDelay = 50;    // the debounce time; increase if the output flickers

// This is to keep track of what menu settings the encoder is changing
int menu_length = 2; // how many menus are there
int menu_index = 0; // start on menu 0 (order goes 0, 1, 2 ...)

void increment_menu(){
  // add one to current index when comparing to number of menus to make it 1-indexed instead of 0
  if((menu_index + 1) < menu_length){
    menu_index++;
  }else{
    menu_index = 0;
  }
}

void increment_delay(){
  if(speed_delay_index < speed_delay_MAX){
    speed_delay_index++;
    speed_delay = (int) (speed_array[speed_delay_index]);
  }
}

void decrement_delay(){
  if(speed_delay_index > speed_delay_MIN){
    speed_delay_index--;
    speed_delay = (int) (speed_array[speed_delay_index]);
  }
}

void increment_brightness(){
  if(brightness_index < brightness_index_MAX){
    brightness_index++;
    brightness = (unsigned int) (brightness_array[brightness_index]);
    strip.setBrightness(brightness);
  }
}

void decrement_brightness(){
  if(brightness_index > brightness_index_MIN){
    brightness_index--;
    brightness = (unsigned int) (brightness_array[brightness_index]);
    strip.setBrightness(brightness);
  }
}

void decrement_value(){
  switch(menu_index){
    case 0:
      decrement_delay();
      break;
    case 1:
      decrement_brightness();
      break;
    default:
      decrement_delay();
      break;
  }
}

void increment_value(){
  switch(menu_index){
    case 0:
      increment_delay();
      break;
    case 1:
      increment_brightness();
      break;
    default:
      increment_delay();
      break;
  }
}

void setup() {
  strip.begin();
  strip.show(); // Initialize all pixels to 'off'
  
  //Serial.begin(9600);

  pinMode(PIN_ENCODER_SWITCH, INPUT);
  // the switch is active-high, not active-low
  // since it shares the pin with Trinket's built-in LED
  // the LED acts as a pull-down resistor
  digitalWrite(PIN_ENCODER_SWITCH, HIGH);

}

int pos = 0, dir = 1; // Position, direction of "eye"

void loop() {
  
  long newPosition = myEnc.read();
  
  if (newPosition > oldPosition) {
    oldPosition = newPosition;
    increment_value();
    //Serial.println("speed_delay: " + String(speed_delay) + " speed_delay_index: " + String(speed_delay_index) );
    //Serial.println("brightness: " + String(brightness) + " brightness_index: " + String(brightness_index) + " brightness_index_array: " + String(brightness_array[brightness_index]) );
  }
  else if(newPosition < oldPosition){
    oldPosition = newPosition;
    decrement_value();
    //Serial.println("speed_delay: " + String(speed_delay) + " speed_delay_index: " + String(speed_delay_index) );
    //Serial.println("brightness: " + String(brightness) + " brightness_index: " + String(brightness_index) + " brightness_index_array: " + String(brightness_array[brightness_index]) );
  }

  // remember that the switch is active-low
  if (digitalRead(PIN_ENCODER_SWITCH)==LOW) 
  {
    if (sw_was_pressed == 0) // only on initial press, so the keystroke is not repeated while the button is held down
    {
      increment_menu();
      //Serial.println("Button down");
      delay(5); // debounce delay
    }
    sw_was_pressed = 1;
  }
  else
  {
    if (sw_was_pressed != 0) {
      delay(5); // debounce delay
    }
    sw_was_pressed = 0;
  }
  
   int j;
 
  // Draw 5 pixels centered on pos. setPixelColor() will clip any
  // pixels off the ends of the strip, we don't need to watch for that.
  strip.setPixelColor(pos - 2, 0x100000); // Dark red
  strip.setPixelColor(pos - 1, 0x800000); // Medium red
  strip.setPixelColor(pos , 0xFF3000); // Center pixel is brightest
  strip.setPixelColor(pos + 1, 0x800000); // Medium red
  strip.setPixelColor(pos + 2, 0x100000); // Dark red
  
  // Draw 5 pixels centered on pos. setPixelColor() will clip any
  // pixels off the ends of the strip, we don't need to watch for that.
  strip.setPixelColor((strip.numPixels()-1) - pos - 2, 0x100000); // Dark red
  strip.setPixelColor((strip.numPixels()-1) - pos - 1, 0x800000); // Medium red
  strip.setPixelColor((strip.numPixels()-1) - pos , 0xFF3000); // Center pixel is brightest
  strip.setPixelColor((strip.numPixels()-1) - pos + 1, 0x800000); // Medium red
  strip.setPixelColor((strip.numPixels()-1) - pos + 2, 0x100000); // Dark red
 
  strip.show();
  delay(speed_delay);
  //delayMicroseconds(speed_delay);
 
  // Rather than being sneaky and erasing just the tail pixel,
  // it's easier to erase it all and draw a new one next time.
  for(j=-2; j<= 2; j++) strip.setPixelColor(pos+j, 0);
  for(j=-2; j<= 2; j++) strip.setPixelColor( (strip.numPixels()-1) - pos+j, 0);
 
  // Bounce off ends of strip
  pos += dir;
  if(pos < 0) {
    pos = 1;
    dir = -dir;
  } else if(pos >= strip.numPixels()/2) {
    pos = strip.numPixels()/2 - 2;
    dir = -dir;
  }
}

