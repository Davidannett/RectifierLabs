// Paint example specifically for the TFTLCD breakout board.
// If using the Arduino shield, use the tftpaint_shield.pde sketch instead!
// DOES NOT CURRENTLY WORK ON ARDUINO LEONARDO

#include <Adafruit_GFX.h>    // Core graphics library
#include <Adafruit_TFTLCD.h> // Hardware-specific library
#include <TouchScreen.h>

#if defined(__SAM3X8E__)
    #undef __FlashStringHelper::F(string_literal)
    #define F(string_literal) string_literal
#endif



#define YP A3  // must be an analog pin, use "An" notation!
#define XM A2  // must be an analog pin, use "An" notation!
#define YM 9   // can be a digital pin
#define XP 8   // can be a digital pin

#define TS_MINX 150
#define TS_MINY 120
#define TS_MAXX 920
#define TS_MAXY 940

// For better pressure precision, we need to know the resistance
// between X+ and X- Use any multimeter to read it
// For the one we're using, its 300 ohms across the X plate
TouchScreen ts = TouchScreen(XP, YP, XM, YM, 300);

#define LCD_CS A3
#define LCD_CD A2
#define LCD_WR A1
#define LCD_RD A0
// optional
#define LCD_RESET A4

// Assign human-readable names to some common 16-bit color values:
#define	BLACK   0x0000
#define	BLUE    0x001F
#define	RED     0xF800
#define	GREEN   0x07E0
#define CYAN    0x07FF
#define MAGENTA 0xF81F
#define YELLOW  0xFFE0
#define WHITE   0xFFFF


Adafruit_TFTLCD tft(LCD_CS, LCD_CD, LCD_WR, LCD_RD, LCD_RESET);

//#define BOXSIZE 40
//#define PENRADIUS 3
//int oldcolor, currentcolor;
//
//
// 
//  pinMode(13, OUTPUT);


#define MINPRESSURE 10
#define MAXPRESSURE 1000

void drawLine(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1, uint16_t color);

// drawHomeScreen - Custom Function
//void drawHomeScreen() {
//  // Title
//  //tft.setBackColor(0,0,0); // Sets the background color of the area where the text will be printed to black
//  tft.setTextColor(WHITE); // Sets color to white
//  tft.setTextSize(4); // Sets font to big
//  tft.text("Arduino TFT Tutorial", CENTER, 10); // Prints the string on the screen
//  tft.setTextColor(RED); // Sets color to red
//  tft.drawLine(0,32,319,32); // Draws the red line
//  tft.setTextColor(WHITE); // Sets color to white
//  tft.setTextSize(4); // Sets the font to small
//  tft.text("by HowToMechatronics.com", CENTER, 41); // Prints the string
//  tft.setTextSize(4);
//  tft.text("Select Example", CENTER, 64);
  
  // Button - Distance Sensor
//  tft.setColor(16, 167, 103); // Sets green color
//  tft.fillRoundRect (35, 90, 285, 130); // Draws filled rounded rectangle
//  tft.setColor(255, 255, 255); // Sets color to white
//  tft.drawRoundRect (35, 90, 285, 130); // Draws rounded rectangle without a fill, so the overall appearance of the button looks like it has a frame
//  tft.setFont(BigFont); // Sets the font to big
//  tft.setBackColor(16, 167, 103); // Sets the background color of the area where the text will be printed to green, same as the button
//  tft.print("DISTANCE SENSOR", CENTER, 102); // Prints the string
