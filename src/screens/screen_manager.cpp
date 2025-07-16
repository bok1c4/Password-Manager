#include <./screens/screen_interface.h>
#include <./screens/screen_manager.h>
#include <memory>

void ScreenManager::push(std::unique_ptr<PaneInterface> screen) {
  screen_stack.push(std::move(screen));
}

void ScreenManager::pop() {
  if (!screen_stack.empty()) {
    screen_stack.pop();
  }
}

PaneInterface *ScreenManager::current() {
  if (screen_stack.empty())
    return nullptr;
  return screen_stack.top().get();
}

bool ScreenManager::empty() const { return screen_stack.empty(); }
