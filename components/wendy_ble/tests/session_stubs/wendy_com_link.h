#pragma once
struct wcom_operation { void (*func)(struct wcom_operation *); struct wcom_operation *next; };
void wcom_core_exec(struct wcom_operation *);
