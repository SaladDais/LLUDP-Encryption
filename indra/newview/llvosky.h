/** 
 * @file llvosky.h
 * @brief LLVOSky class header file
 *
 * $LicenseInfo:firstyear=2001&license=viewerlgpl$
 * Second Life Viewer Source Code
 * Copyright (C) 2010, Linden Research, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License only.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 * Linden Research, Inc., 945 Battery Street, San Francisco, CA  94111  USA
 * $/LicenseInfo$
 */

#ifndef LL_LLVOSKY_H
#define LL_LLVOSKY_H

#include "stdtypes.h"
#include "v3color.h"
#include "v4coloru.h"
#include "llviewertexture.h"
#include "llviewerobject.h"
#include "llframetimer.h"
#include "v3colorutil.h"
#include "llsettingssky.h"
#include "lllegacyatmospherics.h"

const F32 SKY_BOX_MULT			= 16.0f;
const F32 HEAVENLY_BODY_DIST	= HORIZON_DIST - 10.f;
const F32 HEAVENLY_BODY_FACTOR	= 0.1f;
const F32 HEAVENLY_BODY_SCALE	= HEAVENLY_BODY_DIST * HEAVENLY_BODY_FACTOR;

// HACK: Allow server to change sun and moon IDs.
// I can't figure out how to pass the appropriate
// information into the LLVOSky constructor.  JC
//extern LLUUID gSunTextureID;
//extern LLUUID gMoonTextureID;

class LLFace;
class LLHaze;

class LLSkyTex
{
	friend class LLVOSky;
private:
	static S32		sResolution;
	static S32		sComponents;
	LLPointer<LLViewerTexture> mTexture[2];
	LLPointer<LLImageRaw> mImageRaw[2];
	LLColor4		*mSkyData;
	LLVector3		*mSkyDirs;			// Cache of sky direction vectors
	static S32		sCurrent;
	static F32		sInterpVal;

public:
	static F32 getInterpVal()					{ return sInterpVal; }
	static void setInterpVal(const F32 v)		{ sInterpVal = v; }
	static BOOL doInterpolate()					{ return sInterpVal > 0.001f; }

	void bindTexture(BOOL curr = TRUE);
	
protected:
	LLSkyTex();
	void init();
	void cleanupGL();
	void restoreGL();

	~LLSkyTex();


	static S32 getResolution()					{ return sResolution; }
	static S32 getCurrent()						{ return sCurrent; }
	static S32 stepCurrent()					{ sCurrent++; sCurrent &= 1; return sCurrent; }
	static S32 getNext()						{ return ((sCurrent+1) & 1); }
	static S32 getWhich(const BOOL curr)		{ return curr ? sCurrent : getNext(); }

	void initEmpty(const S32 tex);
	
	void create(F32 brightness);

	void setDir(const LLVector3 &dir, const S32 i, const S32 j)
	{
		S32 offset = i * sResolution + j;
		mSkyDirs[offset] = dir;
	}

	const LLVector3 &getDir(const S32 i, const S32 j) const
	{
		S32 offset = i * sResolution + j;
		return mSkyDirs[offset];
	}

	void setPixel(const LLColor4 &col, const S32 i, const S32 j)
	{
		S32 offset = i * sResolution + j;
		mSkyData[offset] = col;
	}

	void setPixel(const LLColor4U &col, const S32 i, const S32 j)
	{
		S32 offset = (i * sResolution + j) * sComponents;
		U32* pix = (U32*) &(mImageRaw[sCurrent]->getData()[offset]);
		*pix = col.asRGBA();
	}

	LLColor4U getPixel(const S32 i, const S32 j)
	{
		LLColor4U col;
		S32 offset = (i * sResolution + j) * sComponents;
		U32* pix = (U32*) &(mImageRaw[sCurrent]->getData()[offset]);
		col.fromRGBA( *pix );
		return col;
	}

	LLImageRaw* getImageRaw(BOOL curr=TRUE)			{ return mImageRaw[getWhich(curr)]; }
	void createGLImage(BOOL curr=TRUE);
};

/// TODO Move into the stars draw pool (and rename them appropriately).
class LLHeavenBody
{
protected:
	LLVector3		mDirectionCached;		// hack for events that shouldn't happen every frame

	LLColor3		mColor;
	LLColor3		mColorCached;
	F32				mIntensity;
	LLVector3		mDirection;				// direction of the local heavenly body
	LLVector3		mAngularVelocity;		// velocity of the local heavenly body

	F32				mDiskRadius;
	bool			mDraw;					// FALSE - do not draw.
	F32				mHorizonVisibility;		// number [0, 1] due to how horizon
	F32				mVisibility;			// same but due to other objects being in throng.
	bool			mVisible;
	static F32		sInterpVal;
	LLVector3		mQuadCorner[4];
	LLVector3		mO;

public:
	LLHeavenBody(const F32 rad);
	~LLHeavenBody() {}

	const LLVector3& getDirection()	const;
	void setDirection(const LLVector3 &direction);
	void setAngularVelocity(const LLVector3 &ang_vel);
	const LLVector3& getAngularVelocity() const;

	const LLVector3& getDirectionCached() const;
	void renewDirection();

	const LLColor3& getColorCached() const;
	void setColorCached(const LLColor3& c);
	const LLColor3& getColor() const;
	void setColor(const LLColor3& c);

	void renewColor();

	static F32 interpVal();
	static void setInterpVal(const F32 v);

	LLColor3 getInterpColor() const;

	const F32& getVisibility() const;
	void setVisibility(const F32 c = 1);

	bool isVisible() const;
	void setVisible(const bool v);

	const F32& getIntensity() const;
	void setIntensity(const F32 c);

	void setDiskRadius(const F32 radius);
	F32	getDiskRadius()	const;

	void setDraw(const bool draw);
	bool getDraw() const;

	const LLVector3& corner(const S32 n) const;
	LLVector3& corner(const S32 n);
	const LLVector3* corners() const;
};

class LLCubeMap;

class LLVOSky : public LLStaticViewerObject
{
public:	
	enum
	{
		FACE_SIDE0,
		FACE_SIDE1,
		FACE_SIDE2,
		FACE_SIDE3,
		FACE_SIDE4,
		FACE_SIDE5,
		FACE_SUN, // was 6
		FACE_MOON, // was 7
		FACE_BLOOM, // was 8
		FACE_REFLECTION, // was 10
		FACE_COUNT
	};
	
	LLVOSky(const LLUUID &id, const LLPCode pcode, LLViewerRegion *regionp);

	// Initialize/delete data that's only inited once per class.
	void init();
	void initCubeMap();
	void initEmpty();
	
	void cleanupGL();
	void restoreGL();

	/*virtual*/ void idleUpdate(LLAgent &agent, const F64 &time);
	bool updateSky();
	
	// Graphical stuff for objects - maybe broken out into render class
	// later?
	/*virtual*/ void updateTextures();
	/*virtual*/ LLDrawable* createDrawable(LLPipeline *pipeline);
	/*virtual*/ BOOL		updateGeometry(LLDrawable *drawable);

	const LLHeavenBody& getSun() const						{ return mSun;  }
	const LLHeavenBody& getMoon() const						{ return mMoon; }

	bool isSameFace(S32 idx, const LLFace* face) const { return mFace[idx] == face; }

    // directions provided should already be in CFR coord sys (+x at, +z up, +y right)
    void setSunAndMoonDirectionsCFR(const LLVector3 &sun_dir, const LLVector3 &moon_dir);
    void setSunDirectionCFR(const LLVector3 &sun_direction);
    void setMoonDirectionCFR(const LLVector3 &moon_direction);

	bool updateHeavenlyBodyGeometry(LLDrawable *drawable, const S32 side, LLHeavenBody& hb, const LLVector3 &up, const LLVector3 &right);
	void updateReflectionGeometry(LLDrawable *drawable, F32 H, const LLHeavenBody& HB);
	
	F32 getWorldScale() const							{ return mWorldScale; }
	void setWorldScale(const F32 s)						{ mWorldScale = s; }
	void updateFog(const F32 distance);

    void setFogRatio(const F32 fog_ratio)               { m_legacyAtmospherics.setFogRatio(fog_ratio); }
    F32  getFogRatio() const                            { return m_legacyAtmospherics.getFogRatio(); }

    LLColor4 getSkyFogColor() const                        { return m_legacyAtmospherics.getFogColor(); }
    LLColor4 getGLFogColor() const                      { return m_legacyAtmospherics.getGLFogColor(); }

    LLColor4U getFadeColor() const;

	void setCloudDensity(F32 cloud_density)				{ mCloudDensity = cloud_density; }
	void setWind ( const LLVector3& wind )				{ mWind = wind.length(); }

	const LLVector3 &getCameraPosAgent() const			{ return mCameraPosAgent; }
	LLVector3 getEarthCenter() const					{ return mEarthCenter; }

	LLCubeMap *getCubeMap() const						{ return mCubeMap; }
	S32 getDrawRefl() const								{ return mDrawRefl; }
	void setDrawRefl(const S32 r)						{ mDrawRefl = r; }
	bool isReflFace(const LLFace* face) const			{ return face == mFace[FACE_REFLECTION]; }
	LLFace* getReflFace() const							{ return mFace[FACE_REFLECTION]; }

	LLViewerTexture*	getSunTex() const					{ return mSunTexturep[0];   }
	LLViewerTexture*	getMoonTex() const					{ return mMoonTexturep[0];  }
	LLViewerTexture*	getBloomTex() const					{ return mBloomTexturep;    }

    void setSunTextures(const LLUUID& sun_texture, const LLUUID& sun_texture_next);
    void setMoonTextures(const LLUUID& moon_texture, const LLUUID& moon_texture_next);

	void forceSkyUpdate(void)							{ mForceUpdate = TRUE; }

public:
	LLFace	*mFace[FACE_COUNT];
	LLVector3	mBumpSunDir;

protected:
	~LLVOSky();

	void updateDirections(void);

	void initSkyTextureDirs(const S32 side, const S32 tile);
	void createSkyTexture(const S32 side, const S32 tile);

	LLPointer<LLViewerFetchedTexture> mSunTexturep[2];
	LLPointer<LLViewerFetchedTexture> mMoonTexturep[2];
	LLPointer<LLViewerFetchedTexture> mBloomTexturep;

	static S32			sResolution;
	static S32			sTileResX;
	static S32			sTileResY;
	LLSkyTex			mSkyTex[6];
	LLSkyTex			mShinyTex[6];
	LLHeavenBody		mSun;
	LLHeavenBody		mMoon;
	LLVector3			mSunDefaultPosition;
	LLVector3			mSunAngVel;
	F32					mAtmHeight;
	LLVector3			mEarthCenter;
	LLVector3			mCameraPosAgent;
	F32					mBrightnessScale;
	LLColor3			mBrightestPoint;
	F32					mBrightnessScaleNew;
	LLColor3			mBrightestPointNew;
	F32					mBrightnessScaleGuess;
	LLColor3			mBrightestPointGuess;
	bool				mWeatherChange;
	F32					mCloudDensity;
	F32					mWind;
	
	bool				mInitialized;
	bool				mForceUpdate;				//flag to force instantaneous update of cubemap
	LLVector3			mLastLightingDirection;
	LLColor3			mLastTotalAmbient;
	F32					mAmbientScale;
	LLColor3			mNightColorShift;
	F32					mInterpVal;
	F32					mWorldScale;

	LLPointer<LLCubeMap> mCubeMap;					// Cube map for the environment
	S32					 mDrawRefl;

	LLFrameTimer		mUpdateTimer;

	bool                mHeavenlyBodyUpdated ;

    LLAtmospherics      m_legacyAtmospherics;
};

#endif
