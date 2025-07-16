#include "./screens/note_input_screen.h"
#include "./screens/screen_manager.h"
#include <iostream>

NoteInputScreen::NoteInputScreen(ScreenManager *manager)
    : manager_(manager), focus_index_(0) {}

void NoteInputScreen::render() {}

void NoteInputScreen::handle_input(char key) { std::cout << key << std::endl; }
