package 
{
	import flash.display.Loader;
	import flash.display.Sprite;
	import flash.events.Event;
	import flash.events.EventDispatcher;
	import flash.events.IOErrorEvent;
	import flash.events.SecurityErrorEvent;
	import flash.external.ExternalInterface;
	import flash.net.URLRequest;
	import flash.system.Security;
	import flash.system.SecurityDomain;
	import flash.system.System;
	/**
	 * 加载security.swf
	 * 执行初始化操作和域名安全过滤
	 * 
	 //========example========================================
		package 
		{
			public class Main extends QSecurity 
			{
				public function Main():void 
				{
					super(["*.qq.com","*.gtimg.cn"],0);
				}
				override protected function init():void 
				{
					stage.align = StageAlign.LEFT;
					stage.scaleMode = StageScaleMode.NO_SCALE;
					
					//如：判断一个url是否合法
					if (QSecurity.checkLegalUrl(url))
					{
						this._urlLoader.load(new URLRequest(url));
					}
				}
			}
		}
	//========================================================
	 * @author seanzhu
	 */
	public class QSecurity extends Sprite
	{
		/**
		 * 加载器
		 */
		private var _loader:Loader = new Loader();
		
		/**
		 * 外部调用的接口引用
		 */
		private static var _qSecChecker:Object;
		
		/**
		 * gsec的引用
		 */
		private var _gSec:EventDispatcher;//这个文档类里边包含了qSecChecker静态方法
		/**
		 * 重试次数
		 */
		private var _tryCount:int;
		
		/**
		 * 最大尝试次数
		 */
		private const maxTryCount:int = 5;
		
		/**
		 * 需要指定的域名
		 */
		private var _domains:Array;
		
		/**
		 * 0: 不显示  1: 显示
		 */
		private var _log:int;
		
		/**
		 * 
		 * @param	domains
		 * @param	log
		 */
		public function QSecurity(domains:Array=null,log:int=0)
		{	
			_log = log;
			_domains = domains;
			if(this.stage)
			{
				addToStageHandler();
			}
			else
			{
				this.addEventListener(Event.ADDED_TO_STAGE,addToStageHandler);
			}
		}
		
		
		/**
		 * 
		 * @param e
		 * 
		 */		
		private function addToStageHandler(e:Event=null):void
		{
			e && this.removeEventListener(Event.ADDED_TO_STAGE, addToStageHandler);
			
			if (ExternalInterface.available)
			{
				this.addListener();
			}
			else
			{
				this.init();
			}
		}
		
		/**
		 * 初始化入口
		 */
		protected function init():void
		{
			throw new Error("QSecurity init方法必须被重写");
		}
		
		/**
		 * 
		 * @param	e
		 */
		private function loaderQsecHandler(e:Event):void
		{
			_tryCount++;
			removeListener();
			if (e.type == Event.COMPLETE)
			{
				_gSec = _loader.content as EventDispatcher;
				if (_gSec)
				{
					_gSec.addEventListener(Event.INIT, qSecInitComplete);
					
					_gSec["setData"](this.root.loaderInfo.parameters, _domains,_log);
					
				}
			}
			else if(_tryCount < maxTryCount)
			{
				this.addListener();
			}
			else
			{
				this.init();//放你走吧！
			}
		}
		
		/**
		 * 安全库初始化完成
		 * @param	e
		 */
		private function qSecInitComplete(e:Event):void
		{
			_gSec.removeEventListener(Event.INIT, qSecInitComplete);
			try
			{
				var result:Object = _gSec["result"];
				if (result)
				{
					if (_loader.contentLoaderInfo.applicationDomain.hasDefinition(result.path))
					{
						_qSecChecker = _loader.contentLoaderInfo.applicationDomain.getDefinition(result.path);
					}
					
					if (result.host && _qSecChecker)
					{
						if (checkLegalDomain(result.host))//白名单验证
						{
							Security.allowDomain(result.host);
						}
					}
				}
			}
			catch (err:Error)
			{
				
			}
			this.init();
		}
		
		/**
		 * 一周的缓存
		 */
		private function addListener():void
		{
			this._loader.contentLoaderInfo.addEventListener(Event.COMPLETE, loaderQsecHandler);
			this._loader.contentLoaderInfo.addEventListener(IOErrorEvent.IO_ERROR, loaderQsecHandler);
			this._loader.contentLoaderInfo.addEventListener(SecurityErrorEvent.SECURITY_ERROR, loaderQsecHandler);
			try
			{
				this._loader.load(new URLRequest("http://qzs.qq.com/qzone/client/photo/swf/qsec/security.swf?max_agea=604800"));
			}
			catch (err:Error)
			{
				
			}
		}
		
		/**
		 * 下载侦听器
		 */
		private function removeListener():void
		{
			this._loader.contentLoaderInfo.removeEventListener(Event.COMPLETE, loaderQsecHandler);
			this._loader.contentLoaderInfo.removeEventListener(IOErrorEvent.IO_ERROR, loaderQsecHandler);
			this._loader.contentLoaderInfo.removeEventListener(SecurityErrorEvent.SECURITY_ERROR, loaderQsecHandler);
		}
		
		/**
		 * as3
		 * 检查ObjeckId
		 * 如果发现特殊字符，如：\" \'等，则认为不是合法的id
		 * 这里使用异步，同步在某些浏览器会导致后续的注册addCall失败
		 * 
		 * @param callBack
		 * 
		 */		
		public static function checkObjectId(callBack:Function):void
		{
			_qSecChecker && _qSecChecker.checkObjectId(callBack);
		}
		
		/**
		 * tx允许的大部分域名
		 * 核查域名是否合法
		 */
		public static function checkSetAllowDomain():void
		{
			_qSecChecker && _qSecChecker.checkSetAllowDomain();
		}
		
		/**
		 * 获取传入flashvar参数 
		 * @param vname 参数的名称
		 * @return 参数的值，如果参数不存在则是空的字符串
		 * 
		 */		
		public static function checkGetVar(key:String, defaultStr:String = ""):String
		{
			
			return _qSecChecker?_qSecChecker.checkGetVar(key,defaultStr):defaultStr;
		}
		
		/**
		 * 获取flashvars传进来的函数名，这里控制稍微更加严格 ，只允许合法字符 
		 * @param key
		 * @param defaultStr
		 * @return 
		 * 
		 */		
		public static function checkGetFuncVar(key:String, defaultStr:String = ""):String
		{
			return _qSecChecker?_qSecChecker.checkGetFuncVar(key,defaultStr):defaultStr;
		}
		
		/**
		 * 转换成本地路径
		 * @param	url
		 * @return
		 */
		public static function checkChangeToLocal(url:String):String
		{
			return _qSecChecker?_qSecChecker.checkChangeToLocal(url):"";
		}
		
		/**
		 * 构造函数必须使用2个反斜杠
		 *  判断url是否是被允许的
		 * @return
		 */
		public static function checkLegalUrl(url:String):Boolean {
			return _qSecChecker?_qSecChecker.checkLegalUrl(url):false;
		}
		
		/**
		 * 
		 * @param	host
		 * @return
		 */
		public static function checkLegalDomain(host:String):Boolean
		{
			return _qSecChecker?_qSecChecker.checkLegalDomain(host):false;
		}
		
		
		
		/**
		 * 判断一个url是否是一个本地路径 
		 * @return 
		 * 
		 */		
		public static function checkIsLocalPath(url:String):Boolean
		{
			return _qSecChecker?_qSecChecker.checkIsLocalPath(url):false;
		}
		
		
		/**
		 * " ' \ / xss的源头
		 * 核查参数是否合法，不合法将可能产生xss 
		 * @param param
		 * @return 
		 * 
		 */		
		public static function checkParamLegal(param:String):Boolean
		{
			return _qSecChecker?_qSecChecker.checkParamLegal(param):false;
		}
	}
}