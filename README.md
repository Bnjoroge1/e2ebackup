**End-to-end encrypted backup, using an TEE system such
as AWS Nitro enclaves.**


**TEE:**
Secure Processing: Ensuring that the preparation of data for backup (such as compression and deduplication) is performed in a secure manner, protecting the integrity of the data.
User Authentication: Managing secure user authentication processes to authorize backup and restore operations, ensuring that sensitive operations can only be initiated by authorized users.
Secure Communication: Establishing secure channels for transmitting backup data between the client and the backup server, ensuring that data is encrypted and integrity-protected in transit.
Access Control and Policy Enforcement: Enforcing security policies and access controls for the backup and restore operations within the secure environment provided by the TEE.
**AWS Nitro Enclaves:**
**HSM:(Hardware security model)**
	Key Generation: Securely generating strong encryption keys that will be used to encrypt the backup data before it is stored.
Key Storage: Safely storing the encryption keys, ensuring that they are resistant to extraction even if an attacker gains physical access to the HSM.
Key Management: Handling the lifecycle of keys, including rotation, expiration, and revocation, to maintain the security of the backup data over time.
Encryption and Decryption: Performing cryptographic operations securely within the HSM, thereby minimizing the risk of key exposure.
**S3:**
https://blog.cloudflare.com/opaque-oblivious-passwords
https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/

Resources
https://docs.aws.amazon.com/pdfs/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.pdf
https://engineering.fb.com/2021/09/10/security/whatsapp-e2ee-backups/(used TEE)
https://aws.amazon.com/cloudhsm/(AWS’ cloud Hardware Secuity module system)
https://scontent-iad3-1.xx.fbcdn.net/v/t39.8562-6/241394876_546674233234181_8907137889500301879_n.pdf?_nc_cat=108&ccb=1-7&_nc_sid=e280be&_nc_ohc=EklK4LZKOvIAX-Jjfvd&_nc_ht=scontent-iad3-1.xx&oh=00_AfCc5EeMD2iOBOy81oRKkdoXgoz7nWWptni0x-AwRxzNPQ&oe=65F6BA66
