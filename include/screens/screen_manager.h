#ifndef SCREEN_MANAGER_H
#define SCREEN_MANAGER_H

#include "./screen_interface.h"
#include <memory>
#include <stack>

class PaneInterface;

class ScreenManager {
public:
  void push(std::unique_ptr<PaneInterface> screen);
  void pop();
  PaneInterface *current();

  bool empty() const;

private:
  std::stack<std::unique_ptr<PaneInterface>> screen_stack;
};

#endif // !SCREEN_MANAGER_H
