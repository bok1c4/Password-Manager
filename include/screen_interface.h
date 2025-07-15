#ifndef PANE_INTERFACE_H
#define PANE_INTERFACE_H

class PaneInterface {
public:
    virtual void render() = 0;
    virtual void handle_input(char input) = 0;
    virtual ~PaneInterface() = default;
};

#endif
