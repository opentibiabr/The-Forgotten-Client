/*
  The Forgotten Client
  Copyright (C) 2020 Saiyans King

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

#ifndef __FILE_SURFACE_DIRECT3D9_h_
#define __FILE_SURFACE_DIRECT3D9_h_

#include "engine.h"

#if defined(SDL_VIDEO_RENDER_D3D)

#define DIRECT3D9_MAX_VERTICES 43656
#define DIRECT3D9_MAX_INDICES (DIRECT3D9_MAX_VERTICES * 6 / 4)
#if DIRECT3D9_MAX_INDICES >= 65500
#define DIRECT3D9_USE_UINT_INDICES 1
#else
#define DIRECT3D9_USE_UINT_INDICES 0
#endif

struct VertexD3D9
{
	VertexD3D9(float x, float y, float u, float v, DWORD color) : x(x), y(y), z(0.0f), color(color), u(u), v(v) {}
	VertexD3D9(float x, float y, DWORD color) : x(x), y(y), z(0.0f), color(color), u(0.0f), v(0.0f) {}

	float x, y, z;
	DWORD color;
	float u, v;
};

typedef struct IDirect3DTexture9 IDirect3DTexture9;
struct Direct3D9Texture
{
	Direct3D9Texture() : m_texture(NULL) {}

	operator bool() const {return m_texture;}

	// non-copyable
	Direct3D9Texture(const Direct3D9Texture&) = delete;
	Direct3D9Texture& operator=(const Direct3D9Texture&) = delete;

	// moveable
	Direct3D9Texture(Direct3D9Texture&& rhs) noexcept : 
		m_texture(rhs.m_texture), m_width(rhs.m_width), m_height(rhs.m_height), m_scaleW(rhs.m_scaleW), m_scaleH(rhs.m_scaleH), m_linearSample(rhs.m_linearSample)
	{
		rhs.m_texture = NULL;
	}
	Direct3D9Texture& operator=(Direct3D9Texture&& rhs) noexcept
	{
		if(this != &rhs)
		{
			m_texture = rhs.m_texture;
			m_width = rhs.m_width;
			m_height = rhs.m_height;
			m_scaleW = rhs.m_scaleW;
			m_scaleH = rhs.m_scaleH;
			m_linearSample = rhs.m_linearSample;
			rhs.m_texture = NULL;
		}
		return (*this);
	}

	IDirect3DTexture9* m_texture;
	Uint32 m_width;
	Uint32 m_height;
	float m_scaleW;
	float m_scaleH;
	bool m_linearSample;
};

struct Direct3D9SpriteData
{
	Direct3D9SpriteData() : m_xOffset(0), m_yOffset(0), m_surface(0), m_lastUsage(0) {}

	Uint32 m_xOffset;
	Uint32 m_yOffset;
	Uint32 m_surface;
	Uint32 m_lastUsage;
};

typedef robin_hood::unordered_map<Uint32, Direct3D9Texture> U32BD3D9Textures;
typedef robin_hood::unordered_map<Uint64, Direct3D9SpriteData> U64BD3D9Textures;

typedef struct IDirect3D9 IDirect3D9;
typedef struct IDirect3D9Ex IDirect3D9Ex;
typedef struct IDirect3DDevice9Ex IDirect3DDevice9Ex;
typedef struct IDirect3DSurface9 IDirect3DSurface9;
typedef struct IDirect3DPixelShader9 IDirect3DPixelShader9;
class SurfaceDirect3D9 : public Surface
{
	public:
		SurfaceDirect3D9();
		virtual ~SurfaceDirect3D9();

		// non-copyable
		SurfaceDirect3D9(const SurfaceDirect3D9&) = delete;
		SurfaceDirect3D9& operator=(const SurfaceDirect3D9&) = delete;

		// non-moveable
		SurfaceDirect3D9(const SurfaceDirect3D9&&) = delete;
		SurfaceDirect3D9& operator=(const SurfaceDirect3D9&&) = delete;

		bool createDirect3DTexture(Direct3D9Texture& texture, Uint32 width, Uint32 height, bool linearSampler, bool frameBuffer = false);
		bool updateTextureData(Direct3D9Texture& texture, unsigned char* data);
		void releaseDirect3DTexture(Direct3D9Texture& texture);
		void updateTextureScaling(Direct3D9Texture& texture);

		void initRenderer();
		void resetRenderer();
		void updateRenderer();
		void updateViewport();

		virtual bool isSupported();
		virtual const char* getName() {return "Direct3D9";}
		virtual const char* getSoftware() {return m_software;}
		virtual const char* getHardware() {return m_hardware;}
		virtual Uint32 getVRAM() {return m_totalVRAM;}

		void generateSpriteAtlases();

		void renderTargetsRecreate();
		virtual void init();
		virtual void doResize(Sint32 w, Sint32 h);
		virtual void spriteManagerReset();
		void releaseTextures();
		virtual unsigned char* getScreenPixels(Sint32& width, Sint32& height, bool& bgra);

		virtual void beginScene();
		virtual void endScene();

		Direct3D9Texture* getTextureIndex(Direct3D9Texture* texture);
		void drawQuad(Direct3D9Texture* texture, float vertices[8], float texcoords[8]);
		void drawQuad(Direct3D9Texture* texture, float vertices[8], float texcoords[8], DWORD color);
		void scheduleBatch();

		bool integer_scaling(Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh, Sint32 x, Sint32 y, Sint32 w, Sint32 h);
		virtual void drawLightMap_old(LightMap* lightmap, Sint32 x, Sint32 y, Sint32 scale, Sint32 width, Sint32 height);
		virtual void drawLightMap_new(LightMap* lightmap, Sint32 x, Sint32 y, Sint32 scale, Sint32 width, Sint32 height);
		virtual void drawGameScene(Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh, Sint32 x, Sint32 y, Sint32 w, Sint32 h);
		virtual void beginGameScene();
		virtual void endGameScene();

		virtual void setClipRect(Sint32 x, Sint32 y, Sint32 w, Sint32 h);
		virtual void disableClipRect();
		virtual void drawRectangle(Sint32 x, Sint32 y, Sint32 w, Sint32 h, Sint32 lineWidth, Uint8 r, Uint8 g, Uint8 b, Uint8 a);
		virtual void fillRectangle(Sint32 x, Sint32 y, Sint32 w, Sint32 h, Uint8 r, Uint8 g, Uint8 b, Uint8 a);

		Direct3D9Texture* loadPicture(Uint16 pictureId, bool linear);
		virtual void drawFont(Uint16 pictureId, Sint32 x, Sint32 y, const std::string& text, size_t pos, size_t len, Uint8 r, Uint8 g, Uint8 b, Sint16 cX[256], Sint16 cY[256], Sint16 cW[256], Sint16 cH[256]);
		virtual void drawBackground(Uint16 pictureId, Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh, Sint32 x, Sint32 y, Sint32 w, Sint32 h);
		virtual void drawPictureRepeat(Uint16 pictureId, Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh, Sint32 x, Sint32 y, Sint32 w, Sint32 h);
		virtual void drawPicture(Uint16 pictureId, Sint32 sx, Sint32 sy, Sint32 x, Sint32 y, Sint32 w, Sint32 h);

		bool loadSprite(Uint32 spriteId, Direct3D9Texture* texture, Uint32 xoff, Uint32 yoff);
		bool loadSpriteMask(Uint32 spriteId, Uint32 maskSpriteId, Uint32 outfitColor, Direct3D9Texture* texture, Uint32 xoff, Uint32 yoff);
		virtual void drawSprite(Uint32 spriteId, Sint32 x, Sint32 y);
		virtual void drawSprite(Uint32 spriteId, Sint32 x, Sint32 y, Sint32 w, Sint32 h, Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh);
		virtual void drawSpriteMask(Uint32 spriteId, Uint32 maskSpriteId, Sint32 x, Sint32 y, Uint32 outfitColor);
		virtual void drawSpriteMask(Uint32 spriteId, Uint32 maskSpriteId, Sint32 x, Sint32 y, Sint32 w, Sint32 h, Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh, Uint32 outfitColor);

		Direct3D9Texture* createAutomapTile(Uint32 currentArea);
		void uploadAutomapTile(Direct3D9Texture* texture, Uint8 color[256][256]);
		virtual void drawAutomapTile(Uint32 m_currentArea, bool& m_recreate, Uint8 m_color[256][256], Sint32 x, Sint32 y, Sint32 w, Sint32 h, Sint32 sx, Sint32 sy, Sint32 sw, Sint32 sh);

	protected:
		std::vector<VertexD3D9> m_vertices;
		#if DIRECT3D9_USE_UINT_INDICES > 0
		std::vector<Uint32> m_indices;
		#else
		std::vector<Uint16> m_indices;
		#endif
		std::vector<Direct3D9Texture> m_spritesAtlas;
		U32BD3D9Textures m_automapTiles;
		U64BD3D9Textures m_sprites;
		std::circular_buffer<Uint32, MAX_AUTOMAPTILES> m_automapTilesBuff;
		std::circular_buffer<Uint64, MAX_SPRITES> m_spritesIds;

		Direct3D9Texture* m_pictures = NULL;
		const char* m_software = "Direct3D 9.0";
		char* m_hardware = NULL;

		Direct3D9Texture m_gameWindow;
		Direct3D9Texture m_scaled_gameWindow;

		void* m_d3d9Handle;
		IDirect3D9* m_d3d9 = NULL;
		IDirect3D9Ex* m_d3d9Ex = NULL;
		IDirect3DDevice9* m_device = NULL;
		IDirect3DDevice9Ex* m_deviceEx = NULL;

		IDirect3DSurface9* m_defaultRenderTarget = NULL;
		IDirect3DSurface9* m_currentRenderTarget = NULL;

		Direct3D9Texture* m_binded_texture = NULL;
		IDirect3DPixelShader9* m_pixelShader_sharpen = NULL;

		Sint32 m_maxTextureSize = 1024;
		Sint32 m_integer_scaling_width = 0;
		Sint32 m_integer_scaling_height = 0;

		Sint32 m_adapter = 0;
		Uint32 m_viewPortX = 0;
		Uint32 m_viewPortY = 0;
		Uint32 m_viewPortW = 0;
		Uint32 m_viewPortH = 0;

		Uint32 m_totalVRAM = 0;
		Uint32 m_spriteChecker = 0;
		Uint32 m_currentFrame = 0;
		Uint32 m_cachedVertices = 0;

		Uint32 m_spriteAtlases = 0;
		Uint32 m_spritesPerAtlas = 0;
		Uint32 m_spritesPerModulo = 0;

		bool m_usingLinearSample = false;
		bool m_useAlphaBlending = false;
		bool m_needReset = true;
		bool m_haveSharpening = false;
};

static const DWORD D3D9_sharpen[] =
{
	0xffff0200, 0x002ffffe, 0x42415443, 0x0000001c, 0x0000008f, 0xffff0200,
	0x00000002, 0x0000001c, 0x00008100, 0x00000088, 0x00000044, 0x00000002,
	0x00020001, 0x00000050, 0x00000000, 0x00000060, 0x00000003, 0x00000001,
	0x00000078, 0x00000000, 0x74786574, 0x53657275, 0x00657a69, 0x00030001,
	0x00020001, 0x00000001, 0x00000000, 0x53656874, 0x6c706d61, 0x742b7265,
	0x65546568, 0x72757478, 0xabab0065, 0x00070004, 0x00040001, 0x00000001,
	0x00000000, 0x325f7370, 0x4d00305f, 0x6f726369, 0x74666f73, 0x29522820,
	0x534c4820, 0x6853204c, 0x72656461, 0x6d6f4320, 0x656c6970, 0x30312072,
	0xab00312e, 0x05000051, 0xa00f0001, 0x3e800000, 0x3f800000, 0x3dcccccd,
	0xbd4ccccd, 0x05000051, 0xa00f0002, 0x3f881062, 0x4064dd2f, 0x3eb8d4fe,
	0x3f000000, 0x0200001f, 0x80000000, 0xb0030000, 0x0200001f, 0x90000000,
	0xa00f0800, 0x03000002, 0x80010000, 0xb0000000, 0xa0000000, 0x03000002,
	0x80020000, 0xb0550000, 0xa1550000, 0x03000002, 0x80030001, 0xb0e40000,
	0xa1e40000, 0x03000002, 0x80030002, 0xb0e40000, 0xa0e40000, 0x02000001,
	0x80010003, 0xa1000000, 0x02000001, 0x80020003, 0xa0550000, 0x03000002,
	0x80030003, 0x80e40003, 0xb0e40000, 0x03000042, 0x800f0000, 0x80e40000,
	0xa0e40800, 0x03000042, 0x800f0001, 0x80e40001, 0xa0e40800, 0x03000042,
	0x800f0002, 0x80e40002, 0xa0e40800, 0x03000042, 0x800f0003, 0x80e40003,
	0xa0e40800, 0x03000042, 0x800f0004, 0xb0e40000, 0xa0e40800, 0x03000002,
	0x80070000, 0x80e40000, 0x80e40001, 0x03000002, 0x80070000, 0x80e40002,
	0x80e40000, 0x03000002, 0x80070000, 0x80e40003, 0x80e40000, 0x04000004,
	0x80070000, 0x80e40000, 0xa1000001, 0x80e40004, 0x02000001, 0x80080000,
	0xa0550001, 0x03000009, 0x80180004, 0x80e40000, 0xa0e40002, 0x04000004,
	0x80080004, 0x80ff0004, 0xa0aa0001, 0xa0ff0001, 0x03000002, 0x80170000,
	0x80ff0004, 0x80e40004, 0x02000001, 0x80080000, 0xa0550001, 0x02000001,
	0x800f0800, 0x80e40000, 0x0000ffff
};

#endif
#endif /* __FILE_SURFACE_DIRECT3D9_h_ */
