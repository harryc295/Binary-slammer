#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include "config.h"
#include "logger.h"
#include "rendering/ui.h"

#include <string>

int main(int, char **) {
#ifdef _WIN32
  // Close the console as we are using our own logger
  HWND console = GetConsoleWindow();
  FreeConsole();
  CloseWindow(console);
#endif

  UI *window_instance = UI::get();
  Config *config_instance = Config::get();
  
  if (!window_instance->create_window()) {
    Logger::get()->log("Error: Unable to create a window.", "Main");
    return 1;
  }
  
  while (window_instance->render_frame());
  
  window_instance->destroy_window();

  return 0;
}
