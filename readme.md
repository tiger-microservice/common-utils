# Encrypt/Decrypt with pgp
    [#https://www.baeldung.com/java-bouncy-castle]
    Encryption
    Decryption
    Signature
    Verification

# End to End Encrypt
    Người gửi:
        Tạo khóa AES ngẫu nhiên.
        Mã hóa tin nhắn bằng AES.
        Mã hóa khóa AES bằng public key của người nhận (RSA).
        Gửi tin nhắn đã mã hóa và khóa AES đã mã hóa đến máy chủ.
    Máy chủ:
        Chỉ chuyển tiếp tin nhắn đã mã hóa và khóa AES đã mã hóa đến người nhận.
        Không thể giải mã hoặc đọc nội dung tin nhắn.
    Người nhận:
        Nhận tin nhắn đã mã hóa và khóa AES đã mã hóa.
        Giải mã khóa AES bằng private key của mình (RSA).
        Sử dụng khóa AES để giải mã tin nhắn.