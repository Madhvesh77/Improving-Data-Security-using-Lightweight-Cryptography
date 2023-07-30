# Improving-Data-Security-using-Lightweight-Cryptography
A Django web application consisting of two interconnected apps: the Sender and the Receiver. The sender has 3 forms of data to encrypt. The receiver can decrypt the data and can view the results of bit-flipping attack and dictionary attack. 
The Sender app allows users to encrypt data (text, file, or image) using a new lightweight cryptography algorithm that operates on a Feistel structure and includes logical operations. The encrypted data is then securely stored on the local machine. 
The Receiver app allows users to decrypt the received ciphertext using the appropriate decryption key. Additionally, the Receiver app provides options to analyze the security of the encryption algorithm by performing bit-flipping attacks and dictionary attacks, along with displaying the UACI and NPCR values when encrypting images.
Key Features:

1. Sender App:
   - User Interface: The Sender app presents users with a user-friendly interface that includes three options to encrypt data: Text, File, and Image.
   - Encryption Process: When a user selects a particular data type to encrypt, the system applies the lightweight cryptography algorithm with 5 rounds and a Feistel structure along with logical operations for encryption.
   - Automatic Encryption: The selected data is automatically encrypted upon clicking the 'Encrypt' button and securely stored on the local machine.
   - Security Assurance: The Sender app ensures that the encryption process is robust and provides a secure channel for data transfer to the Receiver.

2. Receiver App:
   - User Interface: The Receiver app provides a clean interface with a single 'Decrypt' button to initiate the decryption process.
   - Decryption Process: Upon clicking the 'Decrypt' button, the system fetches the decryption key and decrypts the received ciphertext.
   - Security Analysis: The Receiver app includes options for bit-flipping attacks and dictionary attacks to assess the strength of the encryption algorithm.
   - Image Encryption Analysis: When encrypting images, the app displays the UACI (Unified Average Changed Intensity) and NPCR (Normalized Pixel Change Rate) values, which are metrics used to evaluate the effectiveness of image encryption.

Implementation Details:

1. Django Web Application: The entire system is developed using the Django framework, providing a robust and secure foundation for web application development.

2. Lightweight Cryptography Algorithm: The custom lightweight cryptography algorithm, based on Feistel structure and logical operations, is implemented as a Python function within the application.

3. Secure Data Storage: The encrypted data is securely stored on the local machine using proper encryption and data handling techniques.

4. Security Analysis: The Receiver app includes Python functions for conducting bit-flipping attacks and dictionary attacks on the encrypted data.
