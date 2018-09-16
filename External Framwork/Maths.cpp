#include "Headers.h"

namespace Maths
{
	struct Vector3d
	{
		float x, y, z;
	};

	struct Vector2d
	{
		float x, y;
	};

	struct Matrix4x4
	{
		float _11, _12, _13, _14;
		float _21, _22, _23, _24;
		float _31, _32, _33, _34;
		float _41, _42, _43, _44;
	};

	struct Matrix3x4
	{
		float _11, _12, _13, _14;
		float _21, _22, _23, _24;
		float _31, _32, _33, _34;
	};

	inline float SqaureRoot(const float x)
	{
		union
		{
			int i;
			float x;
		} u;
		u.x = x;
		u.i = (1 << 29) + (u.i >> 1) - (1 << 22);

		u.x = u.x + x / u.x;
		u.x = 0.25f*u.x + x / u.x;

		return u.x;
	}


}