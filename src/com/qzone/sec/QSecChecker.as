/**
 *各种安全过滤，存量和增量多可以使用 
 */
package com.qzone.sec
{
	import flash.external.ExternalInterface;
	import flash.system.Security;
	import flash.utils.clearTimeout;
	import flash.utils.setTimeout;

	public class QSecChecker
	{
		//flashVars 
		public static var flashvars:Object = { };
		
		/**
		 * 设置是否要显示log
		 */
		public static var log:int = 0;
		/**
		 * 合法的域名 
		 */		
		public static var legalDomainList:Array = [];
		
		/**
		 * 
		 * 
		 */		
		public function QSecChecker(){}
		
		/**
		 * 新增的域名 
		 * @param domains
		 * 
		 */		
		public static function pushDomains(domains:Array):void
		{
			if(domains && domains.length > 0)
			{
				legalDomainList = legalDomainList.concat(domains);
			}
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
			if(!Boolean(callBack))throw new Error("必须要设置回调~");
			var _setTimeout:int = setTimeout(setTimeoutHandler,0);
			function setTimeoutHandler():void
			{
				flash.utils.clearTimeout(_setTimeout);
				var objectId:String = ExternalInterface.objectID;
				
				if(!objectId)
				{
					callBack(true);
				}
				else
				{
					var result:Boolean = checkParamLegal(objectId);
					
					jsTrace("objectId result "+result);
					if(result)
					{
						callBack(true);
					}
					else
					{
						callBack(false);
						//throw new Error("检查objectId失败："+objectId);
					}
				}
			}
		}
		
		/**
		 * 获取传入flashvar参数 
		 * @param vname 参数的名称
		 * @return 参数的值，如果参数不存在则是空的字符串
		 * 
		 */		
		public static function checkGetVar(key:String, defaultStr:String = ""):String
		{
			var return_str:String = defaultStr;
			if(flashvars && flashvars[key] != undefined)
			{
				return_str = flashvars[key];
			}
			return return_str;
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
			var return_str:String = defaultStr;
			if(flashvars && flashvars[key] != undefined)
			{
				return_str = flashvars[key];
				return_str = return_str.replace(/[^0-9a-zA-Z_.]/g, "");
				if (return_str == "alert" || return_str == "eval" || return_str == "window.open")
				{
					return_str = "";
				}
			}
			return return_str;
		}
		
		/**
		 * 转换成本地路径
		 * @param	url
		 * @return
		 */
		public static function checkChangeToLocal(url:String):String
		{
			if (url)
			{
				url = trim(url);
				url = url.replace(/^(https?:)?\/\/.+?\/+/gi, "/");
				return url;
			}
			return "";
		}
		
		/**
		 * 构造函数必须使用2个反斜杠
		 *  判断url是否是被允许的
		 * @return
		 */
		public static function checkLegalUrl(url:String):Boolean {
			//var exp:RegExp = /^(((http|https):\/\/[\d\w-\.]+\.(qq\.com|pengyou\.com|gtimg\.cn)\/))/gi;
			if(!url || checkIsLocalPath(url))//本地合法
			{
				return true;
			}
			var host:String = url.split("/")[2];
			return checkLegalDomain(host);
			//return exp.test(url);
		}
		
		/**
		 * 
		 * @param	host
		 * @return
		 */
		public static function checkLegalDomain(host:String):Boolean
		{
			jsTrace("host.length "+host.length);
			jsTrace("QSecchecker host "+host);
			if(!host)
			{
				return false;//包括被构造的/// 及https://////
			}
			host = host.toLocaleLowerCase();
			
			jsTrace("QSecchecker legalDomainList " + legalDomainList);
			var index:int;
			var key:String;
			for each(key in legalDomainList)
			{
				key = key.toLocaleLowerCase().replace("*","");
				
				index = host.indexOf(key);
				
				if(index != -1)
				{
					if(index + key.length == host.length)//防止构造
					{
						return true;
					}
				}
			}
			return false;
		}
		
		/**
		 * 检查是否在空间应用
		 * @return
		 */
		public static function checkInQzone():Boolean
		{
			var inQzone:String = ExternalInterface.call("window.QZONE.toString");
			if (!inQzone || inQzone == "null")
			{
				return false;
			}
			return true;
		}
		
		/**
		 * 提供来不停的取host
		 * @return 
		 * 
		 */
		public static function getHost():String
		{
			var host:String = ExternalInterface.call("function(){return window.location.host;}");
			return host;
		}
		
		/**
		 * 判断一个url是否是一个本地路径 
		 * @return 
		 * 
		 */		
		public static function checkIsLocalPath(url:String):Boolean
		{
			url = trim(url);
			var reg:RegExp = /^(http:\/\/|https:\/\/|\/\/)/gi;
			return !reg.test(url);
		}
		
		/**
		 * 
		 * @param	str
		 * @return
		 */
		private static function trim(str:String):String
		{
			if (str)
			{
				str = str.replace(/\s/g,"");
			}
			return str;
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
			//var reg:RegExp = /\"|\'|\\|\//gi;//范围太大 。尽量收弄
			var reg:RegExp = /[^\w-.]/gi;
			return !reg.test(param);
		}
		
		/**
		 * 
		 * @return 
		 * 
		 */		
		public static function get isAvailable():Boolean
		{
			return ExternalInterface.available;
		}
		/**
		 * 
		 * @param	...args
		 */
		public static function jsTrace(...args):void
		{
			if (log)
			{
				if (ExternalInterface.available)
				{
					ExternalInterface.call('console.log', new Date().getTime() + '----' + args.join(' '));
				}
				else
				{
					trace(new Date().getTime() + '----' + args.join(' '));
				}
			}
		}
		
		//======================================特别为单机版准备=========================================================================
		
		/**
		 * 此接口提供给单机版使用，就是不想加载swf,老项目使用
		 * tx允许的大部分域名
		 * 核查域名是否合法
		 */
		public static function checkSetAllowDomain():void
		{
			try
			{
				var host:String = QSecChecker.getHost();
				jsTrace("checkSetAllowDomain host "+host);
				if (checkLegalDomain(host))
				{
					jsTrace("checkSetAllowDomain host白名单验证通过");
					Security.allowDomain(host);
				}
			}
			catch (err:Error)
			{
			}
		}
		//=================================================================================================
	}
}