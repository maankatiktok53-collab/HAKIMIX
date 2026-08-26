import base64
import urllib.parse
import hashlib
import binascii
from colorama import Fore, Style, init

init(autoreset=True)

def generate_ntlm(text):
    """Abuurista NTLM hash (UTF-16LE MD4)."""
    try:
        ntlm_hash = hashlib.new('md4', text.encode('utf-16le')).hexdigest()
        return ntlm_hash
    except Exception:
        # Fallback haddii md4 algorithm uusan ku jirin nidaamka
        return "MD4 lama helin nidaamkaaga"

def run_crypto_encoder():
    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║  {Fore.WHITE}🔤 ENCODER, DECODER & HASH GENERATOR TOOLKIT{Fore.CYAN.center(28)}║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}{Style.BRIGHT}DOORO HAWSHA AAD RABTO:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Base64 (Encode / Decode)")
        print(f"  {Fore.GREEN}[2]{Style.RESET_ALL} URL Encoding (Encode / Decode)")
        print(f"  {Fore.GREEN}[3]{Style.RESET_ALL} Hexadecimal (Encode / Decode)")
        print(f"  {Fore.GREEN}[4]{Style.RESET_ALL} Binary (Text to Binary / Binary to Text)")
        print(f"  {Fore.GREEN}[5]{Style.RESET_ALL} Hash Generator (MD5, SHA1, SHA256, SHA512, NTLM)")
        print(f"  {Fore.RED}[0]{Style.RESET_ALL} Dib ugu noqo Menu-ga guud\n")
        
        choice = input(f"{Fore.LIGHTCYAN_EX}Dooro hawl (0-5): {Style.RESET_ALL}").strip()
        
        if choice == "0":
            break
            
        elif choice == "1":
            print(f"\n{Fore.YELLOW}--- BASE64 ENCODER / DECODER ---{Style.RESET_ALL}")
            print("  [1] Qoraal u beddel Base64 (Encode)")
            print("  [2] Base64 ka fur qoraal caadi ah (Decode)")
            sub_choice = input(f"{Fore.LIGHTCYAN_EX}Dooro (1/2): {Style.RESET_ALL}").strip()
            text = input(f"\n{Fore.WHITE}Geli qoraalka: {Style.RESET_ALL}").strip()
            
            if sub_choice == "1":
                encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
                print(f"\n{Fore.GREEN}✅ Base64 Encoded:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{encoded}{Style.RESET_ALL}")
            elif sub_choice == "2":
                try:
                    decoded = base64.b64decode(text.encode('utf-8')).decode('utf-8', errors='replace')
                    print(f"\n{Fore.GREEN}✅ Base64 Decoded:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{decoded}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"\n{Fore.RED}Khalad: Base64 sax ah ma aha ({e}){Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "2":
            print(f"\n{Fore.YELLOW}--- URL ENCODER / DECODER ---{Style.RESET_ALL}")
            print("  [1] URL Encode (e.g. space -> %20)")
            print("  [2] URL Decode (e.g. %20 -> space)")
            sub_choice = input(f"{Fore.LIGHTCYAN_EX}Dooro (1/2): {Style.RESET_ALL}").strip()
            text = input(f"\n{Fore.WHITE}Geli qoraalka/URL-ka: {Style.RESET_ALL}").strip()
            
            if sub_choice == "1":
                encoded = urllib.parse.quote(text)
                print(f"\n{Fore.GREEN}✅ URL Encoded:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{encoded}{Style.RESET_ALL}")
            elif sub_choice == "2":
                decoded = urllib.parse.unquote(text)
                print(f"\n{Fore.GREEN}✅ URL Decoded:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{decoded}{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "3":
            print(f"\n{Fore.YELLOW}--- HEXADECIMAL ENCODER / DECODER ---{Style.RESET_ALL}")
            print("  [1] Text to Hex")
            print("  [2] Hex to Text")
            sub_choice = input(f"{Fore.LIGHTCYAN_EX}Dooro (1/2): {Style.RESET_ALL}").strip()
            text = input(f"\n{Fore.WHITE}Geli xogta: {Style.RESET_ALL}").strip()
            
            if sub_choice == "1":
                encoded = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
                print(f"\n{Fore.GREEN}✅ Hex:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{encoded}{Style.RESET_ALL}")
            elif sub_choice == "2":
                try:
                    cleaned_hex = text.replace(" ", "").replace("0x", "")
                    decoded = binascii.unhexlify(cleaned_hex).decode('utf-8', errors='replace')
                    print(f"\n{Fore.GREEN}✅ Decoded Text:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{decoded}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"\n{Fore.RED}Khalad: Hex sax ah ma aha ({e}){Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "4":
            print(f"\n{Fore.YELLOW}--- BINARY ENCODER / DECODER ---{Style.RESET_ALL}")
            print("  [1] Text to Binary")
            print("  [2] Binary to Text")
            sub_choice = input(f"{Fore.LIGHTCYAN_EX}Dooro (1/2): {Style.RESET_ALL}").strip()
            text = input(f"\n{Fore.WHITE}Geli xogta: {Style.RESET_ALL}").strip()
            
            if sub_choice == "1":
                binary_str = ' '.join(format(ord(c), '08b') for c in text)
                print(f"\n{Fore.GREEN}✅ Binary:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{binary_str}{Style.RESET_ALL}")
            elif sub_choice == "2":
                try:
                    binary_values = text.split()
                    ascii_characters = "".join([chr(int(bv, 2)) for bv in binary_values])
                    print(f"\n{Fore.GREEN}✅ Decoded Text:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{ascii_characters}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"\n{Fore.RED}Khalad: Binary sax ah ma aha ({e}){Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "5":
            print(f"\n{Fore.YELLOW}--- HASH GENERATOR ---{Style.RESET_ALL}")
            text = input(f"{Fore.WHITE}Geli qoraalka ama furaha aad rabto inaad Hash ka dhaliso: {Style.RESET_ALL}").strip()
            if text:
                b_text = text.encode('utf-8')
                md5_val = hashlib.md5(b_text).hexdigest()
                sha1_val = hashlib.sha1(b_text).hexdigest()
                sha256_val = hashlib.sha256(b_text).hexdigest()
                sha512_val = hashlib.sha512(b_text).hexdigest()
                ntlm_val = generate_ntlm(text)
                
                print(f"\n{Fore.CYAN}┌── {Fore.YELLOW}{Style.BRIGHT}HASHES-KA LA DHALIYAY{Fore.CYAN} ──────────────────────────────────┐")
                print(f"│  {Fore.WHITE}MD5:     {Fore.GREEN}{md5_val}")
                print(f"│  {Fore.WHITE}SHA-1:   {Fore.GREEN}{sha1_val}")
                print(f"│  {Fore.WHITE}SHA-256: {Fore.GREEN}{sha256_val}")
                print(f"│  {Fore.WHITE}SHA-512: {Fore.GREEN}{sha512_val[:48]}...")
                print(f"│  {Fore.WHITE}NTLM:    {Fore.GREEN}{ntlm_val}")
                print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")
