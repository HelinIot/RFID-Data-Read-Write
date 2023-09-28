#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 27  // Slave select pin
#define RST_PIN 14  // Reset pin

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Instantiate a MFRC522 reader object.
MFRC522::MIFARE_Key key;          // Create a MIFARE_Key struct named 'key' to hold card information.

int block = 2;  // This is the block number we will write into and then read.

byte blockcontent[16] = {"IOT-IRAN"};  // Data to be written into one of the 64 card blocks.
byte readbackblock[18];  // Array for reading out a block.

void setup() {
  Serial.begin(9600);        // Initialize serial communications with the PC
  SPI.begin();               // Initialize SPI bus
  mfrc522.PCD_Init();        // Initialize MFRC522 card

  Serial.println("Scan a MIFARE Classic card");

  // Prepare the security key for read and write functions.
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;  // Set key bytes
  }
}

void loop() {
  // Look for new cards
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  Serial.println("Card selected");

  // Write data into the card block
  writeBlock(block, blockcontent);

  // Read the block back
  readBlock(block, readbackblock);

  // Print the block contents
  Serial.print("Read block: ");
  for (int j = 0; j < 16; j++) {
    Serial.write(readbackblock[j]);
  }
  Serial.println("");
}

// Write data into a specific block
void writeBlock(int blockNumber, byte arrayAddress[]) {
  // Ensure we only write into data blocks, not trailer blocks
  int largestModulo4Number = blockNumber / 4 * 4;
  int trailerBlock = largestModulo4Number + 3;

  if (blockNumber > 2 && (blockNumber + 1) % 4 == 0) {
    Serial.print(blockNumber);
    Serial.println(" is a trailer block.");
    return;
  }
  Serial.print(blockNumber);
  Serial.println(" is a data block.");

  // Authenticate the desired block for access
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("PCD_Authenticate() failed.");
    return;
  }

  // Write data to the block
  status = mfrc522.MIFARE_Write(blockNumber, arrayAddress, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Write() failed.");
    return;
  }
  Serial.println("Block was written.");
}

// Read data from a specific block
void readBlock(int blockNumber, byte arrayAddress[]) {
  int largestModulo4Number = blockNumber / 4 * 4;
  int trailerBlock = largestModulo4Number + 3;

  // Authenticate the desired block for access
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.print("PCD_Authenticate() failed (read).");
    return;
  }

  // Read the block
  byte bufferSize = 18;
  status = mfrc522.MIFARE_Read(blockNumber, arrayAddress, &bufferSize);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Read() failed.");
    return;
  }
  Serial.println("Block was read.");
}
