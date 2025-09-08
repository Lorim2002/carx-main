# CarX Selector Spammer

A lightweight headlight control automation tool for CarX Drift Racing Online.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)
![Game](https://img.shields.io/badge/game-CarX%20Drift%20Racing%20Online-orange)

# <img alt="gif" src="https://i.imgur.com/3vb6mhE.gif">

## Features

- **Smart Window Detection**: Only operates when CarX is active
- **Multiple Operation Modes**:
  - Normal Spam Mode (Adjustable speed)
  - Police Flasher Mode with various patterns:
    - Normal Pattern
    - Fast Pattern
    - Ultra Pattern
    - Advanced Strobo Pattern (Complex sequence)
- **Real-time Status Monitoring**
- **Customizable Speed Control**
- **User-friendly Interface**

## Controls

- `F6`: Toggle Normal Spam Mode
- `F5`: Toggle Police Flasher Mode
- `1-4`: Select flasher patterns in Police Mode
- `F7/F8`: Adjust speed in Normal Mode
- `ESC`: Exit Program

## Installation

1. Download the latest release
2. Run the executable as administrator
3. Make sure CarX Drift Racing Online is running
4. Use the controls to activate desired mode

## Requirements

- Windows OS
- CarX Drift Racing Online (Steam version)
- Administrator privileges

## Building from Source

```bash
# Using Visual Studio:
1. Open CarXSpammer.sln
2. Build Solution (F7)
3. Find executable in Debug/Release folder

# Using g++:
g++ main.cpp -o CarXSpammer.exe
```

## Usage Notes

- Run as administrator for proper key simulation
- Only works when CarX window is active
- Adjustable spam speed from 5ms to 100ms
- Multiple police flasher patterns available

## Disclaimer

This tool is for educational purposes only. Use at your own risk.

## Credits

Created by @majorkadev

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Version History

- v1.0 (2025)
  - Initial release
  - Added multiple flasher patterns
  - Added speed control
  - Added window detection 
