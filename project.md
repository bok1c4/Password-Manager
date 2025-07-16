✅ High-Level Architecture & Strategy

To achieve this flow, we’ll introduce:

1. Screen Navigation Stack

   Keep track of the current screen (already done)

   Add support for pushing/popping screens to enable multi-step flows (like entering and confirming a password)

2. Input Focus Management

   Use a focus_index to track which UI element is "selected" (like input field vs back button)

   Use <TAB> to cycle focus, <ENTER> to activate the focused item

3. OOP Design for Screens

   Each screen inherits from PaneInterface

   Screens can render state, handle input, and request navigation changes (e.g., push another screen)
