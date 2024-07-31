import pyotp

# Misalnya, menggunakan token rahasia dari pengguna
secret = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(secret)
print("Current OTP:", totp.now())
