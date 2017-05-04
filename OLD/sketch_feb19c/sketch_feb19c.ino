// This sketch has been Refurbished by BUHOSOFT
// IMPORTANT: Adafruit_TFTLCD LIBRARY MUST BE SPECIFICALLY
// CONFIGURED FOR EITHER THE TFT SHIELD OR THE BREAKOUT BOARD.
// SEE RELEVANT COMMENTS IN Adafruit_TFTLCD.h FOR SETUP.
//#define DEBUG
#include <Adafruit_GFX.h>    // Core graphics library
#include <Adafruit_TFTLCD.h> // Hardware-specific library

// The control pins for the LCD can be assigned to any digital or
// analog pins...but we'll use the analog pins as this allows us to
// double up the pins with the touch screen (see the TFT paint example).
#define LCD_CS A3 // Chip Select goes to Analog 3
#define LCD_CD A2 // Command/Data goes to Analog 2
#define LCD_WR A1 // LCD Write goes to Analog 1
#define LCD_RD A0 // LCD Read goes to Analog 0

#define LCD_RESET A4 // Can alternately just connect to Arduino's reset pin



// Assign human-readable names to some common 16-bit color values:
#define  BLACK   0x0000
#define BLUE    0x001F
#define RED     0xF800
#define GREEN   0x07E0
#define CYAN    0x07FF
#define MAGENTA 0xF81F
#define YELLOW  0xFFE0
#define WHITE   0xFFFF

Adafruit_TFTLCD tft(LCD_CS, LCD_CD, LCD_WR, LCD_RD, LCD_RESET);
// If using the shield, all control and data lines are fixed, and
// a simpler declaration can optionally be used:
// Adafruit_TFTLCD tft;

void setup() 
{
   TFT_BL_ON;                                          //turn on the background light 
 
    Tft.TFTinit();                                      //init TFT library             
 
    Tft.drawCircle(100, 100, 30,YELLOW);                //center: (100, 100), r = 30 ,color : YELLOW              
 
    Tft.drawCircle(100, 200, 40,CYAN);                  //center: (100, 200), r = 10 ,color : CYAN  
 
    Tft.fillCircle(200, 100, 30,RED);                   //center: (200, 100), r = 30 ,color : RED    
 
    Tft.fillCircle(200, 200, 30,BLUE);                  //center: (200, 200), r = 30 ,color : BLUE                 
}
 
void loop()
{
 
}
