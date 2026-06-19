#ifndef UI_H_
#define UI_H_

#include <GLFW/glfw3.h>

#include "../../incl/imgui.h"
#include "../../incl/imgui_impl_glfw.h"
#include "../../incl/imgui_impl_opengl3.h"
#include "../../incl/imgui_internal.h"

#include "../singleton.h"

class UI : public singleton<UI> {
public:
  UI() = default;

  bool create_window();
  void destroy_window();

  bool render_frame();

private:
  GLFWwindow *m_window;

  static void glfw_error_callback(int error, const char *description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
  }
};

#endif // !UI_H_
