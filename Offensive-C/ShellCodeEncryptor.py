def main():
    buf = [
        0xfc, 0x48, 0x83, 0xe4, 0xf0,  
    ]

    encoded = [(byte + 2) & 0xFF for byte in buf]

    hex_string = ", ".join(f"0x{byte:02x}" for byte in encoded)

    print("The payload is:", hex_string)

if __name__ == "__main__":
    main()
