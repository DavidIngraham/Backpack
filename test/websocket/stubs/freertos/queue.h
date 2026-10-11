#pragma once
#include <deque>
#include <vector>
#include <cstring>
struct TestQueue { size_t capacity, size; std::deque<std::vector<unsigned char>> items; };
using QueueHandle_t = TestQueue*;
inline QueueHandle_t xQueueCreate(size_t n, size_t s) { return new TestQueue{n,s,{}}; }
inline int xQueueSend(QueueHandle_t q, const void *v, int) {
 if(q->items.size()==q->capacity) return 0;
 const auto *p=static_cast<const unsigned char*>(v);
 q->items.emplace_back(p,p+q->size); return 1;
}
inline int xQueueReceive(QueueHandle_t q, void *v, int) {
 if(q->items.empty()) return 0;
 memcpy(v,q->items.front().data(),q->size); q->items.pop_front(); return 1;
}
