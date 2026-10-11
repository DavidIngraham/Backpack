#pragma once
#include "../../../websocket/stubs/freertos/queue.h"
inline void vQueueDelete(QueueHandle_t q) { delete q; }
