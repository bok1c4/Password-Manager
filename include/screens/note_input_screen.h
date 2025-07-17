#include "./screens/screen_interface.h"
#include "./screens/screen_manager.h"
#include <string>
#ifndef NOTE_INPUT_SCREEN_H
#define NOTE_INPUT_SCREEN_H()

class NoteInputScreen : public PaneInterface {
public:
  NoteInputScreen(ScreenManager *manager, const std::string &password);

  void render() override;
  void handle_input(std::string input) override;

private:
  ScreenManager *manager_;
  PaneInterface *current;
  std::string password_;
  std::string note_;
};

#endif // !DEBUG
