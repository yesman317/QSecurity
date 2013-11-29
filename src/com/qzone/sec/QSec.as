/**
 *flash xss 安全库 包括flash初始化检测等等 
 * 
 * 袁库 1：c 2：没设置allowDomain就call 3:添加右键菜单 4：init也有问题
 * 取host的时候 还没设置llowDomain 
 */
package com.qzone.sec
{
	import flash.display.Sprite;
	import flash.display.StageAlign;
	import flash.display.StageScaleMode;
	import flash.events.DataEvent;
	import flash.events.Event;
	import flash.events.EventDispatcher;
	import flash.events.SampleDataEvent;
	import flash.events.TimerEvent;
	import flash.external.ExternalInterface;
	import flash.system.Capabilities;
	import flash.system.Security;
	import flash.utils.Timer;

	/**
	 * qzone team 
	 * seanzhu neilcui lanceluo
	*/
	public class QSec extends Sprite
	{
		/**
		 * 安全及初始化入口，增量flash可以继承此类
		 * 
		 */		
		public function QSec()
		{
			Security.allowDomain("*");
		}
		
		/**
		 * 
		 * @param	flashvars
		 * @param	domains
		 */
		public function setData(flashvars:Object,domains:Array=null,log:int=0):void
		{
			QSecChecker.log = log;
			QSecChecker.pushDomains(domains);
			QSecChecker.flashvars = flashvars;
			excuteData();
		}
		
		/** 
		 * 继承后重写此方法
		 */		
		protected function init():void
		{
			QSecChecker.jsTrace("qsec init");
			this.dispatchEvent(new Event(Event.INIT));
		}
		
		/**
		 * 
		 * @param e
		 * 
		 */		
		private function excuteData():void
		{
			QSecChecker.jsTrace("qsec excuteData");
			
			if(!QSecChecker.isAvailable)//调试模式跳过一切检测
			{
				QSecChecker.jsTrace("调试模式跳过一切检测");
				this.init();
			}
			else
			{
				QSecChecker.jsTrace("验证objects");
				//异步验证object,只有成功才返回，不成功抛错，考虑到使用的方便
				//OzUtils.reportCode(QSecIds.domain,QSecIds.cgi,1,QSecIds.addToStage);
				QSecChecker.checkObjectId(checkObjectIdSucc);
			}
		}
		
		/**
		 * objeckId检查是否通过
		 * 如果能通过，则注册一个方法给页面调用
		 * 该方法主要是检测浏览器引擎和虚拟机是否准备好
		 * @param param
		 * 
		 */		
		private function checkObjectIdSucc(param:Boolean):void
		{
			QSecChecker.jsTrace("ExternalInterface.objectID " + ExternalInterface.objectID);
			QSecChecker.jsTrace("param " + param);
			if (param)
			{
				this.startTimer(1);
			}
			else
			{
				QSecChecker.jsTrace("QSec里边没ObjectId检查通过");
				//OzUtils.reportCode(QSecIds.domain, QSecIds.cgi, 2, QSecIds.objIdFailed);
				throw new Error("objectId没检查通过");
			}
			
		}
		
		/**
		 * 
		 * @param timerHandler
		 * 
		 */		
		private function startTimer(step:int):void
		{
			this._currStep = step;
			this._timer.addEventListener(TimerEvent.TIMER,timerHandler);
			this._timer.addEventListener(TimerEvent.TIMER_COMPLETE,timerHandler);
			this._timer.start();
		}
		
		/**
		 * 集中处理timer事件
		 */		
		private function timerHandler(e:TimerEvent):void
		{
			if(e.type ==  TimerEvent.TIMER_COMPLETE)
			{
				QSecChecker.jsTrace("time out");
				this.clearTimer();
				switch(this._currStep)
				{
					case 1://说明getHost失败，那不管了，不设置allowDomain
						this.startTimer(2);
						break;
					case 2:
						this.init();
						break;
				}
			}
			else
			{
				switch(this._currStep)
				{
					case 1:
						QSecChecker.jsTrace(1);
						var host:String = QSecChecker.getHost();
						if(host)
						{
							_result.getHost = true;
							_result.host = host;
							this.clearTimer();
							//QSecChecker.checkSetAllowDomain();
							this.startTimer(2);
							
							if (QSecChecker.checkLegalDomain(host))
							{
								_result.checkHostOk = true;
								Security.allowDomain(host);
							}
						}
						break;
					case 2:
						QSecChecker.jsTrace(2);
						if(this.flashCallFlashTimerHandler())
						{
							_result.flashCallFlash = true;
							this.clearTimer();
							this.init();
						}
						break;
				}
			}
		}
		
		
		/**
		 * 不停的注册 不停的获取注册的方法是否成功
		 * @param e
		 * 
		 */		
		private function flashCallFlashTimerHandler():Boolean
		{
				flash.external.ExternalInterface.addCallback(triggerFlashInit,triggerFlashInitCallBack);
				
				var _flashCallFlash:String = flashCallFlash();
				QSecChecker.jsTrace("_flashCallFlash "+_flashCallFlash);
				if(!_flashCallFlash || _flashCallFlash == "undefined")
				{
					return false;
				}
				return true;
		}
		
		/**
		 * 给页面一个返回值，用来判断调用成功的关键
		 * @return 
		 * 
		 */		
		private function triggerFlashInitCallBack():String
		{
			return "flashCallFlashSuccess";
		}
		
		
		/**
		 * flash 自己注册一个方法，然后通过页面中转 看是否能访问到自己的方法 
		 * @return 
		 * 
		 */		
		private function flashCallFlash():String
		{
			var flashId:String = ExternalInterface.objectID;
			var jsId:String = '(document["' + flashId + '"] || window["' + flashId + '"])';
			QSecChecker.jsTrace("flashId "+flashId);
			QSecChecker.jsTrace("jsId " + jsId);
			
			var myTriggerFlashInit:String = ExternalInterface.call("function(){return " + jsId + "."+triggerFlashInit+"() + '';}");
			
			return myTriggerFlashInit;
		}
		
		/**
		 * 清除timer事件
		 */		
		private function clearTimer():void
		{
			_timer.stop();
			_timer.removeEventListener(TimerEvent.TIMER,this.timerHandler);
			_timer.removeEventListener(TimerEvent.TIMER_COMPLETE,this.timerHandler);
			_timer.reset();
		}
		
		/**
		 *定时 
		 */		
		private var _timer:Timer = new Timer(100,20);
		
		private var _currStep:int;//1:检查getHost 2:检查flashCallFlash //检查objectId目前没纳入
		
		/**
		 * flash 注册一个方法，让页面尝试调用。
		 * 当检测到该方法存在，说明flash 调用页面成功，同时页面也调用flash成功
		 */		
		private const triggerFlashInit:String = "triggerFlashInit";
		
		/**
		 * 更多的信息给qloader 目的是方便统计
		 */
		private var _result:Object = {path:"com.qzone.sec.QSecChecker"};
		
		public function get result():Object 
		{
			return _result;
		}
	}
}