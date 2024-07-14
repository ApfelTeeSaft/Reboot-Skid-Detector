#include "../Hooks.h"
#include "../../Configs/Config.h"

// Original function pointer
typedef void(*ClientReturnToMainMenu_t)();
ClientReturnToMainMenu_t oClientReturnToMainMenu = nullptr;

// Hook function
void __fastcall hkClientReturnToMainMenu() {
    if (Config::Exploits::Server::NullifyClientReturnToMainMenu) {
        return;
    }
    else {
        // Call the original function, idk what it is tho lol so KEEP IT ON FFS!
    }
}