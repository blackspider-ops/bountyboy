# 🧪 BountyBoy Vulnerable Lab

A local environment with intentionally vulnerable applications for testing BountyBoy.

## ⚠️ WARNING

These applications are **INTENTIONALLY VULNERABLE**. 
- Only run on isolated networks
- Never expose to the internet
- For educational purposes only

## 🚀 Quick Start

```bash
# Start all vulnerable apps
docker-compose up -d

# Wait ~2 minutes for everything to initialize
# Check status
docker-compose ps
```

## 🎯 Available Targets

| App | URL | Description | Best For Testing |
|-----|-----|-------------|------------------|
| **DVWA** | http://localhost:8080 | Classic PHP vulns | SQLi, XSS, CSRF, File Upload |
| **Juice Shop** | http://localhost:3000 | Modern Node.js app | IDOR, JWT, API vulns, XSS |
| **WebGoat** | http://localhost:8081/WebGoat | Learning platform | All OWASP Top 10 |
| **bWAPP** | http://localhost:8082 | 100+ vulnerabilities | Comprehensive testing |
| **NodeGoat** | http://localhost:4000 | Node.js OWASP | Injection, Auth bypass |

## 🔧 Setup Instructions

### DVWA Setup
1. Go to http://localhost:8080
2. Login: `admin` / `password`
3. Click "Create / Reset Database"
4. Set Security Level to "Low" for testing

### Juice Shop
1. Go to http://localhost:3000
2. No setup needed - start hacking!
3. Check the scoreboard at `/#/score-board`

### WebGoat
1. Go to http://localhost:8081/WebGoat
2. Register a new account
3. Follow the lessons

### bWAPP
1. Go to http://localhost:8082/install.php
2. Click "Install"
3. Login: `bee` / `bug`

### NodeGoat
1. Go to http://localhost:4000
2. Register a new account
3. Explore the vulnerable features

## 🧪 DVWA Security Level Testing

BountyBoy includes a dedicated DVWA tester (`test_dvwa.py`) that tests all security levels:

### Running the DVWA Tester

```bash
source venv/bin/activate
python test_dvwa.py
```

### Security Levels Explained

| Level | Description | Expected Results |
|-------|-------------|------------------|
| **LOW** | No protection | All payloads work |
| **MEDIUM** | Basic filtering | Some bypasses work |
| **HIGH** | Strict filtering | Advanced bypasses needed |
| **IMPOSSIBLE** | Secure code | Nothing should work |

### Test Results by Security Level

#### LOW Security
- ✅ SQLi: All payloads work (`' OR '1'='1`, UNION, etc.)
- ✅ XSS: All payloads work (`<script>`, event handlers)
- ✅ Command Injection: All payloads work (`;`, `|`, `&&`)
- ✅ LFI: All payloads work (`../../../etc/passwd`)

#### MEDIUM Security
- ✅ SQLi: No-quote payloads work (`1 OR 1=1`)
- ✅ XSS: Event handlers work (`<img onerror>`)
- ✅ Command Injection: Pipe works (`|id`)
- ✅ LFI: Double-dot bypass works

#### HIGH Security
- ✅ SQLi: Hash comment bypass (`#`)
- ✅ XSS: Alternative tags work (`<img>`, `<svg>`)
- ✅ Command Injection: Newline bypass works
- ✅ LFI: File protocol works (`file:///`)

#### IMPOSSIBLE Security
- ❌ SQLi: Properly parameterized queries
- ❌ XSS: Proper output encoding
- ❌ Command Injection: Whitelist validation
- ❌ LFI: Whitelist file access

### Getting Your PHPSESSID

1. Login to DVWA at http://localhost:8080
2. Open browser DevTools (F12)
3. Go to Application → Cookies
4. Copy the `PHPSESSID` value

## 🎮 Testing with BountyBoy

### Add to /etc/hosts (for subdomain testing)
```bash
sudo sh -c 'echo "127.0.0.1 dvwa.local juiceshop.local webgoat.local bwapp.local nodegoat.local" >> /etc/hosts'
```

### Run BountyBoy
```bash
cd ..
source venv/bin/activate

# Quick test on Juice Shop
python ultimate.py -t localhost:3000 --quick --learn

# Full scan on DVWA
python ultimate.py -t localhost:8080 --standard --learn --report

# Test specific modules
python ultimate.py -t localhost:3000 --full --learn
```

### What Each App Tests

**DVWA (localhost:8080)**
- ✅ SQLi Scanner
- ✅ XSS Scanner  
- ✅ Path Fuzzer
- ✅ Security Headers
- ✅ CSRF (manual)

**Juice Shop (localhost:3000)**
- ✅ IDOR Scanner
- ✅ JWT Analyzer
- ✅ API Fuzzer
- ✅ XSS Scanner
- ✅ SQLi Scanner
- ✅ JS Analyzer (lots of secrets!)
- ✅ Open Redirect

**WebGoat (localhost:8081)**
- ✅ All vulnerability types
- ✅ Great for learning

**bWAPP (localhost:8082)**
- ✅ SSRF
- ✅ XXE
- ✅ All OWASP Top 10

## 🛑 Stopping the Lab

```bash
# Stop all containers
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## 💡 Tips

1. **Start with Juice Shop** - Most modern, best documented
2. **Use DVWA for basics** - Classic vulns, adjustable difficulty
3. **Check WebGoat lessons** - Explains each vulnerability
4. **Run with --learn flag** - BountyBoy explains what it's doing
5. **Test IMPOSSIBLE level** - Verify your scanner doesn't have false positives

## 🔗 Resources

- [DVWA Guide](https://github.com/digininja/DVWA)
- [Juice Shop Pwning Guide](https://pwning.owasp-juice.shop/)
- [WebGoat Lessons](https://owasp.org/www-project-webgoat/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
