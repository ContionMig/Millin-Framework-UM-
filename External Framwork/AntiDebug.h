#pragma once
#include "Headers.h"

// https://github.com/mrexodia/TitanHide/blob/master/TitanHideTest/main.cpp
namespace AntiDebug
{
	extern inline BOOLEAN CheckNtClose();
	extern inline BOOLEAN CheckSystemDebugControl();
	extern inline BOOLEAN CheckSystemDebugger();
	extern inline BOOLEAN CheckObjectList();
	extern inline BOOLEAN HideFromDebugger();
	extern inline BOOLEAN CheckProcessDebugObjectHandle();
	extern inline BOOLEAN CheckProcessDebugPort();
	extern inline BOOLEAN CheckProcessDebugFlags();
	extern inline BOOLEAN CheckDevices();
	extern inline BOOLEAN CheckProcess();
}