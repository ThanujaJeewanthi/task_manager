<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up()
    {
        Schema::create('pages', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('code');
            $table->foreignId('page_category_id')->constrained('page_categories')->onDelete('cascade');
            $table->boolean('active')->default(true);
            $table->timestamps();

        });
    }

    public function down()
    {
        Schema::dropIfExists('pages');
    }
}
;
